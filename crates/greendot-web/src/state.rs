//! Desired-state store. SQLite is the source of truth; configfs is treated
//! as a disposable cache that the reconciler keeps in sync.

use anyhow::{Context, Result};
use greendot_proto::{Iqn, Nqn};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

/// Every export we create lives under these prefixes; reconciliation never
/// touches configfs objects outside them. Defined in the shared protocol crate
/// so the helper scopes its configfs writes to the same prefix.
pub use greendot_proto::{OUR_IQN_PREFIX, OUR_NQN_PREFIX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Nvme,
    Iscsi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub id: i64,
    pub kind: ExportKind,
    pub name: String,
    pub device_path: String,
    pub enabled: bool,
    pub want_rdma: bool,
    pub want_tcp: bool,
    pub want_loop: bool,
    pub allow_any_host: bool,
    pub initiators: Vec<String>,
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
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('nvme','iscsi')),
    name TEXT NOT NULL UNIQUE,
    device_path TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    want_rdma INTEGER NOT NULL,
    want_tcp INTEGER NOT NULL,
    want_loop INTEGER NOT NULL DEFAULT 0,
    allow_any_host INTEGER NOT NULL DEFAULT 1,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS export_initiators (
    export_id INTEGER NOT NULL REFERENCES exports(id) ON DELETE CASCADE,
    initiator TEXT NOT NULL,
    UNIQUE(export_id, initiator)
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshot_policies (
    id INTEGER PRIMARY KEY,
    dataset TEXT NOT NULL,
    cron TEXT NOT NULL,
    prefix TEXT NOT NULL,
    keep_last INTEGER,
    keep_days INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run INTEGER NOT NULL DEFAULT 0
);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPolicy {
    pub id: i64,
    pub dataset: String,
    pub cron: String,
    pub prefix: String,
    pub keep_last: Option<u32>,
    pub keep_days: Option<u32>,
    pub enabled: bool,
    /// Unix timestamp of the last firing (0 = never).
    pub last_run: i64,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_export(&self, new: &NewExport) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO exports (kind, name, device_path, want_rdma, want_tcp, want_loop, allow_any_host)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                match new.kind {
                    ExportKind::Nvme => "nvme",
                    ExportKind::Iscsi => "iscsi",
                },
                new.name,
                new.device_path,
                new.want_rdma,
                new.want_tcp,
                new.want_loop,
                new.allow_any_host,
            ],
        )?;
        let id = tx.last_insert_rowid();
        for initiator in &new.initiators {
            tx.execute(
                "INSERT OR IGNORE INTO export_initiators (export_id, initiator) VALUES (?1, ?2)",
                rusqlite::params![id, initiator],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn list_exports(&self) -> Result<Vec<Export>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, kind, name, device_path, enabled, want_rdma, want_tcp, want_loop,
                    allow_any_host, last_error
             FROM exports ORDER BY name",
        )?;
        let mut exports: Vec<Export> = stmt
            .query_map([], |row| {
                Ok(Export {
                    id: row.get(0)?,
                    kind: if row.get::<_, String>(1)? == "nvme" {
                        ExportKind::Nvme
                    } else {
                        ExportKind::Iscsi
                    },
                    name: row.get(2)?,
                    device_path: row.get(3)?,
                    enabled: row.get(4)?,
                    want_rdma: row.get(5)?,
                    want_tcp: row.get(6)?,
                    want_loop: row.get(7)?,
                    allow_any_host: row.get(8)?,
                    initiators: Vec::new(),
                    last_error: row.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut stmt =
            conn.prepare("SELECT export_id, initiator FROM export_initiators ORDER BY initiator")?;
        for row in stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })? {
            let (id, initiator) = row?;
            if let Some(export) = exports.iter_mut().find(|e| e.id == id) {
                export.initiators.push(initiator);
            }
        }
        Ok(exports)
    }

    pub fn set_export_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE exports SET enabled = ?1 WHERE id = ?2",
            rusqlite::params![enabled, id],
        )?;
        Ok(())
    }

    pub fn set_export_error(&self, id: i64, error: Option<&str>) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE exports SET last_error = ?1 WHERE id = ?2",
            rusqlite::params![error, id],
        )?;
        Ok(())
    }

    pub fn delete_export(&self, id: i64) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM exports WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query_map([key], |row| row.get(0))?;
        Ok(rows.next().transpose()?)
    }

    pub fn insert_policy(&self, p: &SnapshotPolicy) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO snapshot_policies (dataset, cron, prefix, keep_last, keep_days, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                p.dataset,
                p.cron,
                p.prefix,
                p.keep_last,
                p.keep_days,
                p.enabled
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_policies(&self) -> Result<Vec<SnapshotPolicy>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, dataset, cron, prefix, keep_last, keep_days, enabled, last_run
             FROM snapshot_policies ORDER BY dataset",
        )?;
        let policies = stmt
            .query_map([], |row| {
                Ok(SnapshotPolicy {
                    id: row.get(0)?,
                    dataset: row.get(1)?,
                    cron: row.get(2)?,
                    prefix: row.get(3)?,
                    keep_last: row.get(4)?,
                    keep_days: row.get(5)?,
                    enabled: row.get(6)?,
                    last_run: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(policies)
    }

    pub fn set_policy_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE snapshot_policies SET enabled = ?1 WHERE id = ?2",
            rusqlite::params![enabled, id],
        )?;
        Ok(())
    }

    pub fn set_policy_last_run(&self, id: i64, last_run: i64) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE snapshot_policies SET last_run = ?1 WHERE id = ?2",
            rusqlite::params![last_run, id],
        )?;
        Ok(())
    }

    pub fn delete_policy(&self, id: i64) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM snapshot_policies WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
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
}
