//! Desired-state store. The export/settings/policy config is the source of
//! truth and lives in a hand-editable TOML file; task run-history stays in
//! SQLite. configfs is treated as a disposable cache the reconciler keeps in
//! sync.

use anyhow::{Context, Result};
use greendot_proto::{Iqn, Nqn};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Every export we create lives under these prefixes; reconciliation never
/// touches configfs objects outside them. Defined in the shared protocol crate
/// so the helper scopes its configfs writes to the same prefix.
pub use greendot_proto::{OUR_IQN_PREFIX, OUR_NQN_PREFIX};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportKind {
    Nvme,
    Iscsi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    pub id: i64,
    pub kind: ExportKind,
    pub name: String,
    pub device_path: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub want_rdma: bool,
    pub want_tcp: bool,
    #[serde(default)]
    pub want_loop: bool,
    #[serde(default = "default_true")]
    pub allow_any_host: bool,
    #[serde(default)]
    pub initiators: Vec<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl Export {
    pub fn nqn(&self) -> Nqn {
        Nqn::new(format!("{OUR_NQN_PREFIX}{}", self.name))
            .expect("validated name forms a valid NQN")
    }

    pub fn iqn(&self) -> Iqn {
        Iqn::new(format!("{OUR_IQN_PREFIX}{}", self.name))
            .expect("validated name forms a valid IQN")
    }
}

pub struct NewExport {
    pub kind: ExportKind,
    pub name: String,
    pub device_path: String,
    pub want_rdma: bool,
    pub want_tcp: bool,
    pub want_loop: bool,
    pub allow_any_host: bool,
    pub initiators: Vec<String>,
}

pub struct Db {
    /// Task run-history — the one table that stays in SQLite.
    conn: Mutex<Connection>,
    /// Desired-state config (exports, settings, snapshot policies).
    config: Mutex<ConfigDoc>,
    /// Where `config` is persisted as TOML. `None` in tests => never writes.
    path: Option<PathBuf>,
}

/// The TOML document backing the desired-state config; the domain structs
/// (`Export`, `SnapshotPolicy`) serialize directly into it.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct ConfigDoc {
    /// Monotonic id counters, never reused, so URLs stay stable across deletes.
    next_export_id: i64,
    next_policy_id: i64,
    settings: BTreeMap<String, String>,
    export: Vec<Export>,
    policy: Vec<SnapshotPolicy>,
}

fn default_true() -> bool {
    true
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    command TEXT NOT NULL DEFAULT '',
    args TEXT NOT NULL DEFAULT '[]',
    stdin TEXT,
    stdout TEXT NOT NULL DEFAULT '',
    stderr TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    exit_code INTEGER,
    error TEXT,
    started_at INTEGER NOT NULL,
    finished_at INTEGER
);
";

/// How many finished tasks to retain.
pub const TASK_RETENTION: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Running,
    Success,
    Failed,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskStatus::Running => "running",
            TaskStatus::Success => "success",
            TaskStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: i64,
    pub kind: String,
    pub title: String,
    pub command: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub status: TaskStatus,
    pub exit_code: Option<i64>,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPolicy {
    pub id: i64,
    pub dataset: String,
    pub cron: String,
    pub prefix: String,
    #[serde(default)]
    pub keep_last: Option<u32>,
    #[serde(default)]
    pub keep_days: Option<u32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Unix timestamp of the last firing (0 = never).
    #[serde(default)]
    pub last_run: i64,
}

impl Db {
    /// Opens the task-history SQLite at `tasks_db` and loads the desired-state
    /// config from `state_path`, writing a default file if it does not exist.
    pub fn open(tasks_db: &Path, state_path: &Path) -> Result<Self> {
        let conn = Connection::open(tasks_db)
            .with_context(|| format!("opening {}", tasks_db.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        let db = Db {
            conn: Mutex::new(conn),
            config: Mutex::new(load_config(state_path)?),
            path: Some(state_path.to_owned()),
        };
        // First boot: materialize the default config on disk so it is present
        // and discoverable for hand-editing.
        db.persist(&db.config.lock().unwrap())?;
        Ok(db)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
            config: Mutex::new(ConfigDoc::default()),
            path: None,
        })
    }

    /// Atomically rewrites the config TOML (temp file + rename). A no-op when
    /// `path` is `None`, as in tests.
    fn persist(&self, doc: &ConfigDoc) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let text = toml::to_string_pretty(doc).context("serializing state config")?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }

    pub fn insert_export(&self, new: &NewExport) -> Result<i64> {
        let mut doc = self.config.lock().unwrap();
        if doc.export.iter().any(|e| e.name == new.name) {
            anyhow::bail!("an export named {:?} already exists", new.name);
        }
        doc.next_export_id += 1;
        let id = doc.next_export_id;
        doc.export.push(Export {
            id,
            kind: new.kind,
            name: new.name.clone(),
            device_path: new.device_path.clone(),
            enabled: true,
            want_rdma: new.want_rdma,
            want_tcp: new.want_tcp,
            want_loop: new.want_loop,
            allow_any_host: new.allow_any_host,
            initiators: dedup_preserve(&new.initiators),
            last_error: None,
        });
        self.persist(&doc)?;
        Ok(id)
    }

    pub fn list_exports(&self) -> Result<Vec<Export>> {
        let mut exports = self.config.lock().unwrap().export.clone();
        exports.sort_by(|a, b| a.name.cmp(&b.name));
        for e in &mut exports {
            e.initiators.sort();
        }
        Ok(exports)
    }

    pub fn set_export_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.export.iter_mut().find(|e| e.id == id) {
            e.enabled = enabled;
        }
        self.persist(&doc)
    }

    pub fn set_export_error(&self, id: i64, error: Option<&str>) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.export.iter_mut().find(|e| e.id == id) {
            e.last_error = error.map(str::to_owned);
        }
        self.persist(&doc)
    }

    pub fn delete_export(&self, id: i64) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        doc.export.retain(|e| e.id != id);
        self.persist(&doc)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.config.lock().unwrap().settings.get(key).cloned())
    }

    pub fn insert_policy(&self, p: &SnapshotPolicy) -> Result<i64> {
        let mut doc = self.config.lock().unwrap();
        doc.next_policy_id += 1;
        let id = doc.next_policy_id;
        doc.policy.push(SnapshotPolicy {
            id,
            last_run: 0,
            ..p.clone()
        });
        self.persist(&doc)?;
        Ok(id)
    }

    pub fn list_policies(&self) -> Result<Vec<SnapshotPolicy>> {
        let mut policies = self.config.lock().unwrap().policy.clone();
        policies.sort_by(|a, b| a.dataset.cmp(&b.dataset));
        Ok(policies)
    }

    pub fn set_policy_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(p) = doc.policy.iter_mut().find(|p| p.id == id) {
            p.enabled = enabled;
        }
        self.persist(&doc)
    }

    pub fn set_policy_last_run(&self, id: i64, last_run: i64) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(p) = doc.policy.iter_mut().find(|p| p.id == id) {
            p.last_run = last_run;
        }
        self.persist(&doc)
    }

    pub fn delete_policy(&self, id: i64) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        doc.policy.retain(|p| p.id != id);
        self.persist(&doc)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        doc.settings.insert(key.to_owned(), value.to_owned());
        self.persist(&doc)
    }

    /// Records a started task; returns its id. Command/args/stdin land via
    /// [`Db::set_task_command`] once the helper reports them.
    pub fn insert_task(&self, kind: &str, title: &str, started_at: i64) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tasks (kind, title, status, started_at) VALUES (?1, ?2, 'running', ?3)",
            rusqlite::params![kind, title, started_at],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn set_task_command(
        &self,
        id: i64,
        command: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> Result<()> {
        let args = serde_json::to_string(args).unwrap_or_else(|_| "[]".into());
        self.conn.lock().unwrap().execute(
            "UPDATE tasks SET command = ?1, args = ?2, stdin = ?3 WHERE id = ?4",
            rusqlite::params![command, args, stdin, id],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finish_task(
        &self,
        id: i64,
        status: TaskStatus,
        exit_code: Option<i64>,
        error: Option<&str>,
        stdout: &str,
        stderr: &str,
        finished_at: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE tasks SET status = ?1, exit_code = ?2, error = ?3, stdout = ?4, stderr = ?5,
                              finished_at = ?6 WHERE id = ?7",
            rusqlite::params![
                status.as_str(),
                exit_code,
                error,
                stdout,
                stderr,
                finished_at,
                id
            ],
        )?;
        // Bound history to the most recent rows.
        conn.execute(
            "DELETE FROM tasks WHERE id NOT IN (SELECT id FROM tasks ORDER BY id DESC LIMIT ?1)",
            [TASK_RETENTION],
        )?;
        Ok(())
    }

    pub fn list_tasks(&self, limit: i64) -> Result<Vec<Task>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM tasks ORDER BY id DESC LIMIT ?1")?;
        let tasks = stmt
            .query_map([limit], row_to_task)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(tasks)
    }

    pub fn get_task(&self, id: i64) -> Result<Option<Task>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM tasks WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], row_to_task)?;
        Ok(rows.next().transpose()?)
    }
}

fn row_to_task(row: &rusqlite::Row) -> rusqlite::Result<Task> {
    let status = match row.get::<_, String>("status")?.as_str() {
        "success" => TaskStatus::Success,
        "failed" => TaskStatus::Failed,
        _ => TaskStatus::Running,
    };
    let args: Vec<String> =
        serde_json::from_str(&row.get::<_, String>("args")?).unwrap_or_default();
    Ok(Task {
        id: row.get("id")?,
        kind: row.get("kind")?,
        title: row.get("title")?,
        command: row.get("command")?,
        args,
        stdin: row.get("stdin")?,
        stdout: row.get("stdout")?,
        stderr: row.get("stderr")?,
        status,
        exit_code: row.get("exit_code")?,
        error: row.get("error")?,
        started_at: row.get("started_at")?,
        finished_at: row.get("finished_at")?,
    })
}

/// The desired state needed to reconcile, read straight from the config TOML.
pub struct Desired {
    pub exports: Vec<Export>,
    pub listen: IpAddr,
}

/// Reads the desired state from `state_path` with no side effects (no SQLite,
/// no first-boot write), so `greendot-cli reconcile` only ever *reads* config —
/// the web service stays the sole writer. Exports are normalized exactly as
/// [`Db::list_exports`] returns them.
pub fn read_desired(state_path: &Path) -> Result<Desired> {
    let doc = load_config(state_path)?;
    let mut exports = doc.export;
    exports.sort_by(|a, b| a.name.cmp(&b.name));
    for e in &mut exports {
        e.initiators.sort();
    }
    let listen = doc
        .settings
        .get("listen_addr")
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    Ok(Desired { exports, listen })
}

/// Reads the desired-state config from `path`, or the default document if the
/// file does not exist yet (first boot / hand-deleted).
fn load_config(path: &Path) -> Result<ConfigDoc> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigDoc::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Deduplicates initiators while preserving order (replaces the old
/// `INSERT OR IGNORE` on the unique `(export_id, initiator)` index).
fn dedup_preserve(items: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .iter()
        .filter(|s| seen.insert(s.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new(name: &str) -> NewExport {
        NewExport {
            kind: ExportKind::Nvme,
            name: name.into(),
            device_path: "/dev/zvol/tank/vm1".into(),
            want_rdma: true,
            want_tcp: true,
            want_loop: false,
            allow_any_host: false,
            initiators: vec!["nqn.2014-08.org.nvmexpress:host1".into()],
        }
    }

    #[test]
    fn task_lifecycle_and_retention() {
        let db = Db::in_memory().unwrap();
        let id = db
            .insert_task("zvol-create", "create tank/vm1", 100)
            .unwrap();
        db.set_task_command(id, "zfs", &["create".into(), "tank/vm1".into()], None)
            .unwrap();

        let t = db.get_task(id).unwrap().unwrap();
        assert_eq!(
            (t.kind.as_str(), t.status),
            ("zvol-create", TaskStatus::Running)
        );
        assert_eq!(t.command, "zfs");
        assert_eq!(t.args, ["create", "tank/vm1"]);
        assert_eq!(t.exit_code, None);

        db.finish_task(id, TaskStatus::Success, Some(0), None, "done\n", "", 120)
            .unwrap();
        let t = db.get_task(id).unwrap().unwrap();
        assert_eq!(
            (t.status, t.exit_code, t.stdout.as_str()),
            (TaskStatus::Success, Some(0), "done\n")
        );
        assert_eq!(t.finished_at, Some(120));

        // A failed task with an error message.
        let id2 = db.insert_task("install", "install nvme-cli", 130).unwrap();
        db.finish_task(
            id2,
            TaskStatus::Failed,
            None,
            Some("not installed"),
            "",
            "boom\n",
            131,
        )
        .unwrap();
        let t2 = db.get_task(id2).unwrap().unwrap();
        assert_eq!(t2.status, TaskStatus::Failed);
        assert_eq!(t2.error.as_deref(), Some("not installed"));

        // Newest-first listing.
        let list = db.list_tasks(10).unwrap();
        assert_eq!(list.iter().map(|t| t.id).collect::<Vec<_>>(), vec![id2, id]);

        // Retention prunes to the most recent TASK_RETENTION on finish.
        for i in 0..(TASK_RETENTION + 10) {
            let tid = db.insert_task("noop", "noop", 200 + i).unwrap();
            db.finish_task(tid, TaskStatus::Success, Some(0), None, "", "", 200 + i)
                .unwrap();
        }
        assert_eq!(db.list_tasks(10_000).unwrap().len() as i64, TASK_RETENTION);
        assert!(db.get_task(id).unwrap().is_none(), "oldest task pruned");
    }

    #[test]
    fn export_crud_settings_and_nqn_derivation() {
        let db = Db::in_memory().unwrap();
        let id = db.insert_export(&new("vm1")).unwrap();
        db.insert_export(&new("alpha")).unwrap();
        assert!(
            db.insert_export(&new("vm1")).is_err(),
            "duplicate name must fail"
        );

        let exports = db.list_exports().unwrap();
        assert_eq!(
            exports.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["alpha", "vm1"],
            "sorted by name"
        );
        let vm1 = exports.iter().find(|e| e.id == id).unwrap();
        assert_eq!(vm1.initiators, ["nqn.2014-08.org.nvmexpress:host1"]);
        assert_eq!(vm1.nqn().as_str(), "nqn.2026-06.io.greendot:vm1");
        assert!(vm1.enabled && vm1.want_rdma && vm1.want_tcp && !vm1.want_loop);
        assert_eq!(vm1.last_error, None);

        db.set_export_enabled(id, false).unwrap();
        db.set_export_error(id, Some("rdma bind failed")).unwrap();
        let vm1 = db
            .list_exports()
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap();
        assert!(!vm1.enabled);
        assert_eq!(vm1.last_error.as_deref(), Some("rdma bind failed"));
        db.set_export_error(id, None).unwrap();

        db.delete_export(id).unwrap();
        assert_eq!(db.list_exports().unwrap().len(), 1);

        assert_eq!(db.get_setting("listen_addr").unwrap(), None);
        db.set_setting("listen_addr", "10.0.0.5").unwrap();
        db.set_setting("listen_addr", "10.0.0.6").unwrap();
        assert_eq!(
            db.get_setting("listen_addr").unwrap().as_deref(),
            Some("10.0.0.6")
        );
    }

    #[test]
    fn toml_config_persists_across_reopen_with_stable_ids() {
        let dir = std::env::temp_dir();
        let tag = rand::random::<u32>();
        let tasks_db = dir.join(format!("gd-tasks{tag}.db"));
        let state = dir.join(format!("gd-state{tag}.toml"));

        let (a, b);
        {
            let db = Db::open(&tasks_db, &state).unwrap();
            a = db.insert_export(&new("alpha")).unwrap();
            b = db.insert_export(&new("beta")).unwrap();
            assert!(
                db.insert_export(&new("alpha")).is_err(),
                "duplicate name must fail"
            );
            db.delete_export(a).unwrap();
            db.set_setting("listen_addr", "10.0.0.5").unwrap();
        }
        // Reopen from disk: config survived, ids are not reused after delete.
        {
            let db = Db::open(&tasks_db, &state).unwrap();
            let names: Vec<_> = db
                .list_exports()
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert_eq!(names, ["beta"], "alpha deleted, beta persisted");
            assert_eq!(
                db.get_setting("listen_addr").unwrap().as_deref(),
                Some("10.0.0.5")
            );
            let c = db.insert_export(&new("gamma")).unwrap();
            assert_eq!((a, b, c), (1, 2, 3), "ids never reused across restart");
        }
        for ext in ["db", "db-wal", "db-shm"] {
            std::fs::remove_file(dir.join(format!("gd-tasks{tag}.{ext}"))).ok();
        }
        std::fs::remove_file(&state).ok();
    }
}
