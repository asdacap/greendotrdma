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

/// A block-device export served as an NVMe-oF subsystem. RDMA, TCP and the
/// local loopback are all valid transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeExport {
    pub id: i64,
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

impl NvmeExport {
    pub fn nqn(&self) -> Nqn {
        Nqn::new(format!("{OUR_NQN_PREFIX}{}", self.name))
            .expect("validated name forms a valid NQN")
    }
}

/// A block-device export served as an iSCSI target. RDMA is iSER; there is no
/// loopback transport (so no `want_loop`), and connected sessions are tracked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IscsiExport {
    pub id: i64,
    pub name: String,
    pub device_path: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub want_rdma: bool,
    pub want_tcp: bool,
    #[serde(default = "default_true")]
    pub allow_any_host: bool,
    #[serde(default)]
    pub initiators: Vec<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl IscsiExport {
    pub fn iqn(&self) -> Iqn {
        Iqn::new(format!("{OUR_IQN_PREFIX}{}", self.name))
            .expect("validated name forms a valid IQN")
    }
}

pub struct NewNvmeExport {
    pub name: String,
    pub device_path: String,
    pub want_rdma: bool,
    pub want_tcp: bool,
    pub want_loop: bool,
    pub allow_any_host: bool,
    pub initiators: Vec<String>,
}

pub struct NewIscsiExport {
    pub name: String,
    pub device_path: String,
    pub want_rdma: bool,
    pub want_tcp: bool,
    pub allow_any_host: bool,
    pub initiators: Vec<String>,
}

/// A file-level NFS export of an absolute directory path, served over RDMA.
/// Unlike a block-device export, this has a directory path and a list of
/// client access specs — different enough to warrant its own type/table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsExport {
    pub id: i64,
    pub path: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub clients: Vec<NfsClientEntry>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NfsClientEntry {
    pub client: String,
    #[serde(default = "default_true")]
    pub rw: bool,
}

pub struct NewNfsExport {
    pub path: String,
    pub clients: Vec<NfsClientEntry>,
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
/// (`NvmeExport`, `IscsiExport`, `SnapshotPolicy`) serialize directly into it.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct ConfigDoc {
    /// Monotonic id counters, never reused, so URLs stay stable across deletes.
    next_nvme_export_id: i64,
    next_iscsi_export_id: i64,
    next_policy_id: i64,
    next_nfs_export_id: i64,
    settings: BTreeMap<String, String>,
    nvme_export: Vec<NvmeExport>,
    iscsi_export: Vec<IscsiExport>,
    policy: Vec<SnapshotPolicy>,
    nfs_export: Vec<NfsExport>,
    /// Pre-split configs stored a single unified `export = [...]` table tagged
    /// with `kind`, plus `next_export_id`. These read-only fields capture those
    /// on load; [`migrate_legacy_exports`] splits them into the typed tables.
    /// Never serialized, so they vanish on the next `persist`. Deletable once
    /// every deployment has been upgraded.
    #[serde(default, rename = "export", skip_serializing)]
    legacy_export: Vec<LegacyExport>,
    #[serde(default, rename = "next_export_id", skip_serializing)]
    legacy_next_export_id: i64,
}

/// The pre-split unified export row, read only to migrate it forward.
#[derive(Debug, Clone, Deserialize)]
struct LegacyExport {
    id: i64,
    #[serde(default)]
    kind: String,
    name: String,
    device_path: String,
    #[serde(default = "default_true")]
    enabled: bool,
    want_rdma: bool,
    want_tcp: bool,
    #[serde(default)]
    want_loop: bool,
    #[serde(default = "default_true")]
    allow_any_host: bool,
    #[serde(default)]
    initiators: Vec<String>,
    #[serde(default)]
    last_error: Option<String>,
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

    pub fn insert_nvme_export(&self, new: &NewNvmeExport) -> Result<i64> {
        let mut doc = self.config.lock().unwrap();
        if doc.nvme_export.iter().any(|e| e.name == new.name) {
            anyhow::bail!("an export named {:?} already exists", new.name);
        }
        doc.next_nvme_export_id += 1;
        let id = doc.next_nvme_export_id;
        doc.nvme_export.push(NvmeExport {
            id,
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

    pub fn list_nvme_exports(&self) -> Result<Vec<NvmeExport>> {
        let mut exports = self.config.lock().unwrap().nvme_export.clone();
        exports.sort_by(|a, b| a.name.cmp(&b.name));
        for e in &mut exports {
            e.initiators.sort();
        }
        Ok(exports)
    }

    pub fn set_nvme_export_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.nvme_export.iter_mut().find(|e| e.id == id) {
            e.enabled = enabled;
        }
        self.persist(&doc)
    }

    pub fn set_nvme_export_error(&self, id: i64, error: Option<&str>) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.nvme_export.iter_mut().find(|e| e.id == id) {
            e.last_error = error.map(str::to_owned);
        }
        self.persist(&doc)
    }

    pub fn delete_nvme_export(&self, id: i64) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        doc.nvme_export.retain(|e| e.id != id);
        self.persist(&doc)
    }

    pub fn insert_iscsi_export(&self, new: &NewIscsiExport) -> Result<i64> {
        let mut doc = self.config.lock().unwrap();
        if doc.iscsi_export.iter().any(|e| e.name == new.name) {
            anyhow::bail!("an export named {:?} already exists", new.name);
        }
        doc.next_iscsi_export_id += 1;
        let id = doc.next_iscsi_export_id;
        doc.iscsi_export.push(IscsiExport {
            id,
            name: new.name.clone(),
            device_path: new.device_path.clone(),
            enabled: true,
            want_rdma: new.want_rdma,
            want_tcp: new.want_tcp,
            allow_any_host: new.allow_any_host,
            initiators: dedup_preserve(&new.initiators),
            last_error: None,
        });
        self.persist(&doc)?;
        Ok(id)
    }

    pub fn list_iscsi_exports(&self) -> Result<Vec<IscsiExport>> {
        let mut exports = self.config.lock().unwrap().iscsi_export.clone();
        exports.sort_by(|a, b| a.name.cmp(&b.name));
        for e in &mut exports {
            e.initiators.sort();
        }
        Ok(exports)
    }

    pub fn set_iscsi_export_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.iscsi_export.iter_mut().find(|e| e.id == id) {
            e.enabled = enabled;
        }
        self.persist(&doc)
    }

    pub fn set_iscsi_export_error(&self, id: i64, error: Option<&str>) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.iscsi_export.iter_mut().find(|e| e.id == id) {
            e.last_error = error.map(str::to_owned);
        }
        self.persist(&doc)
    }

    pub fn delete_iscsi_export(&self, id: i64) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        doc.iscsi_export.retain(|e| e.id != id);
        self.persist(&doc)
    }

    /// Device paths backing every managed block export (NVMe-oF + iSCSI), used
    /// to exclude in-use devices from the pool/VG/export creation pickers.
    pub fn export_device_paths(&self) -> Vec<String> {
        let doc = self.config.lock().unwrap();
        doc.nvme_export
            .iter()
            .map(|e| e.device_path.clone())
            .chain(doc.iscsi_export.iter().map(|e| e.device_path.clone()))
            .collect()
    }

    pub fn insert_nfs_export(&self, new: &NewNfsExport) -> Result<i64> {
        let mut doc = self.config.lock().unwrap();
        if doc.nfs_export.iter().any(|e| e.path == new.path) {
            anyhow::bail!("an NFS export of {:?} already exists", new.path);
        }
        doc.next_nfs_export_id += 1;
        let id = doc.next_nfs_export_id;
        doc.nfs_export.push(NfsExport {
            id,
            path: new.path.clone(),
            enabled: true,
            clients: new.clients.clone(),
            last_error: None,
        });
        self.persist(&doc)?;
        Ok(id)
    }

    pub fn list_nfs_exports(&self) -> Result<Vec<NfsExport>> {
        let mut exports = self.config.lock().unwrap().nfs_export.clone();
        exports.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(exports)
    }

    pub fn set_nfs_export_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.nfs_export.iter_mut().find(|e| e.id == id) {
            e.enabled = enabled;
        }
        self.persist(&doc)
    }

    pub fn set_nfs_export_error(&self, id: i64, error: Option<&str>) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        if let Some(e) = doc.nfs_export.iter_mut().find(|e| e.id == id) {
            e.last_error = error.map(str::to_owned);
        }
        self.persist(&doc)
    }

    pub fn delete_nfs_export(&self, id: i64) -> Result<()> {
        let mut doc = self.config.lock().unwrap();
        doc.nfs_export.retain(|e| e.id != id);
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
    pub nvme_exports: Vec<NvmeExport>,
    pub iscsi_exports: Vec<IscsiExport>,
    pub nfs_exports: Vec<NfsExport>,
    pub listen: IpAddr,
}

/// Reads the desired state from `state_path` with no side effects (no SQLite,
/// no first-boot write), so `greendot-cli reconcile` only ever *reads* config —
/// the web service stays the sole writer. Exports are normalized exactly as
/// [`Db::list_nvme_exports`]/[`Db::list_iscsi_exports`] return them.
pub fn read_desired(state_path: &Path) -> Result<Desired> {
    let doc = load_config(state_path)?;
    let mut nvme_exports = doc.nvme_export;
    nvme_exports.sort_by(|a, b| a.name.cmp(&b.name));
    for e in &mut nvme_exports {
        e.initiators.sort();
    }
    let mut iscsi_exports = doc.iscsi_export;
    iscsi_exports.sort_by(|a, b| a.name.cmp(&b.name));
    for e in &mut iscsi_exports {
        e.initiators.sort();
    }
    let mut nfs_exports = doc.nfs_export;
    nfs_exports.sort_by(|a, b| a.path.cmp(&b.path));
    let listen = doc
        .settings
        .get("listen_addr")
        .and_then(|s| s.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    Ok(Desired {
        nvme_exports,
        iscsi_exports,
        nfs_exports,
        listen,
    })
}

/// Reads the desired-state config from `path`, or the default document if the
/// file does not exist yet (first boot / hand-deleted). A pre-split unified
/// `export` table is migrated forward in place (see [`migrate_legacy_exports`]),
/// so both `Db::open` and `read_desired` observe the typed tables.
fn load_config(path: &Path) -> Result<ConfigDoc> {
    let mut doc = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str::<ConfigDoc>(&text)
            .with_context(|| format!("parsing {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigDoc::default(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    migrate_legacy_exports(&mut doc);
    Ok(doc)
}

/// One-shot upgrade of a pre-split config: partition the unified `export` rows
/// into the typed `nvme_export`/`iscsi_export` tables (ids preserved), seed both
/// id counters past every id that ever existed so none is reused, and clear the
/// legacy fields. A no-op once migrated. Idempotent.
fn migrate_legacy_exports(doc: &mut ConfigDoc) {
    if doc.legacy_export.is_empty() {
        return;
    }
    for e in std::mem::take(&mut doc.legacy_export) {
        if e.kind == "iscsi" {
            doc.iscsi_export.push(IscsiExport {
                id: e.id,
                name: e.name,
                device_path: e.device_path,
                enabled: e.enabled,
                want_rdma: e.want_rdma,
                want_tcp: e.want_tcp,
                allow_any_host: e.allow_any_host,
                initiators: e.initiators,
                last_error: e.last_error,
            });
        } else {
            doc.nvme_export.push(NvmeExport {
                id: e.id,
                name: e.name,
                device_path: e.device_path,
                enabled: e.enabled,
                want_rdma: e.want_rdma,
                want_tcp: e.want_tcp,
                want_loop: e.want_loop,
                allow_any_host: e.allow_any_host,
                initiators: e.initiators,
                last_error: e.last_error,
            });
        }
    }
    let max_id = doc
        .nvme_export
        .iter()
        .map(|e| e.id)
        .chain(doc.iscsi_export.iter().map(|e| e.id))
        .max()
        .unwrap_or(0)
        .max(doc.legacy_next_export_id);
    doc.next_nvme_export_id = doc.next_nvme_export_id.max(max_id);
    doc.next_iscsi_export_id = doc.next_iscsi_export_id.max(max_id);
    doc.legacy_next_export_id = 0;
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

    fn new(name: &str) -> NewNvmeExport {
        NewNvmeExport {
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
        let id = db.insert_nvme_export(&new("vm1")).unwrap();
        db.insert_nvme_export(&new("alpha")).unwrap();
        assert!(
            db.insert_nvme_export(&new("vm1")).is_err(),
            "duplicate name must fail"
        );

        let exports = db.list_nvme_exports().unwrap();
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

        db.set_nvme_export_enabled(id, false).unwrap();
        db.set_nvme_export_error(id, Some("rdma bind failed"))
            .unwrap();
        let vm1 = db
            .list_nvme_exports()
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap();
        assert!(!vm1.enabled);
        assert_eq!(vm1.last_error.as_deref(), Some("rdma bind failed"));
        db.set_nvme_export_error(id, None).unwrap();

        db.delete_nvme_export(id).unwrap();
        assert_eq!(db.list_nvme_exports().unwrap().len(), 1);

        assert_eq!(db.get_setting("listen_addr").unwrap(), None);
        db.set_setting("listen_addr", "10.0.0.5").unwrap();
        db.set_setting("listen_addr", "10.0.0.6").unwrap();
        assert_eq!(
            db.get_setting("listen_addr").unwrap().as_deref(),
            Some("10.0.0.6")
        );
    }

    #[test]
    fn iscsi_export_crud_and_iqn_derivation() {
        let db = Db::in_memory().unwrap();
        let new = |name: &str| NewIscsiExport {
            name: name.into(),
            device_path: "/dev/zvol/tank/tape".into(),
            want_rdma: true,
            want_tcp: false,
            allow_any_host: false,
            initiators: vec!["iqn.1993-08.org.debian:01:abc".into()],
        };
        let id = db.insert_iscsi_export(&new("tape")).unwrap();
        assert!(
            db.insert_iscsi_export(&new("tape")).is_err(),
            "duplicate name must fail"
        );
        // iSCSI ids are their own sequence, independent of the NVMe one.
        assert_eq!(id, 1);

        let tape = db.list_iscsi_exports().unwrap();
        let tape = tape.iter().find(|e| e.id == id).unwrap();
        assert_eq!(tape.iqn().as_str(), "iqn.2026-06.io.greendot:tape");
        assert_eq!(tape.initiators, ["iqn.1993-08.org.debian:01:abc"]);

        db.set_iscsi_export_error(id, Some("targetctl failed"))
            .unwrap();
        assert_eq!(
            db.list_iscsi_exports().unwrap()[0].last_error.as_deref(),
            Some("targetctl failed")
        );
        db.delete_iscsi_export(id).unwrap();
        assert!(db.list_iscsi_exports().unwrap().is_empty());
    }

    #[test]
    fn nfs_export_crud_and_duplicate_path() {
        let db = Db::in_memory().unwrap();
        let new = |path: &str| NewNfsExport {
            path: path.into(),
            clients: vec![NfsClientEntry {
                client: "192.168.101.0/24".into(),
                rw: true,
            }],
        };
        let id = db.insert_nfs_export(&new("/tank/share")).unwrap();
        db.insert_nfs_export(&new("/srv/ro")).unwrap();
        assert!(
            db.insert_nfs_export(&new("/tank/share")).is_err(),
            "duplicate path must fail"
        );

        let exports = db.list_nfs_exports().unwrap();
        assert_eq!(
            exports.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            ["/srv/ro", "/tank/share"],
            "sorted by path"
        );
        let share = exports.iter().find(|e| e.id == id).unwrap();
        assert!(share.enabled && share.last_error.is_none());
        assert_eq!(share.clients[0].client, "192.168.101.0/24");

        db.set_nfs_export_enabled(id, false).unwrap();
        db.set_nfs_export_error(id, Some("exportfs failed"))
            .unwrap();
        let share = db
            .list_nfs_exports()
            .unwrap()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap();
        assert!(!share.enabled);
        assert_eq!(share.last_error.as_deref(), Some("exportfs failed"));

        db.delete_nfs_export(id).unwrap();
        assert_eq!(db.list_nfs_exports().unwrap().len(), 1);
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
            a = db.insert_nvme_export(&new("alpha")).unwrap();
            b = db.insert_nvme_export(&new("beta")).unwrap();
            assert!(
                db.insert_nvme_export(&new("alpha")).is_err(),
                "duplicate name must fail"
            );
            db.delete_nvme_export(a).unwrap();
            db.set_setting("listen_addr", "10.0.0.5").unwrap();
        }
        // Reopen from disk: config survived, ids are not reused after delete.
        {
            let db = Db::open(&tasks_db, &state).unwrap();
            let names: Vec<_> = db
                .list_nvme_exports()
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert_eq!(names, ["beta"], "alpha deleted, beta persisted");
            assert_eq!(
                db.get_setting("listen_addr").unwrap().as_deref(),
                Some("10.0.0.5")
            );
            let c = db.insert_nvme_export(&new("gamma")).unwrap();
            assert_eq!((a, b, c), (1, 2, 3), "ids never reused across restart");
        }
        for ext in ["db", "db-wal", "db-shm"] {
            std::fs::remove_file(dir.join(format!("gd-tasks{tag}.{ext}"))).ok();
        }
        std::fs::remove_file(&state).ok();
    }

    #[test]
    fn legacy_unified_export_table_migrates_to_typed_tables() {
        let dir = std::env::temp_dir();
        let tag = rand::random::<u32>();
        let tasks_db = dir.join(format!("gd-mig-tasks{tag}.db"));
        let state = dir.join(format!("gd-mig-state{tag}.toml"));

        // A pre-split config: one unified table tagged with `kind`, plus the old
        // single `next_export_id` counter.
        std::fs::write(
            &state,
            r#"next_export_id = 2

[[export]]
id = 1
kind = "nvme"
name = "vm1"
device_path = "/dev/zvol/tank/vm1"
enabled = true
want_rdma = true
want_tcp = true

[[export]]
id = 2
kind = "iscsi"
name = "tape"
device_path = "/dev/zvol/tank/tape"
enabled = true
want_rdma = true
want_tcp = false
"#,
        )
        .unwrap();

        // Open splits the legacy rows into the typed tables, ids preserved.
        let new_id = {
            let db = Db::open(&tasks_db, &state).unwrap();
            assert_eq!(
                db.list_nvme_exports()
                    .unwrap()
                    .iter()
                    .map(|e| (e.id, e.name.clone()))
                    .collect::<Vec<_>>(),
                [(1, "vm1".to_owned())]
            );
            assert_eq!(
                db.list_iscsi_exports()
                    .unwrap()
                    .iter()
                    .map(|e| (e.id, e.name.clone()))
                    .collect::<Vec<_>>(),
                [(2, "tape".to_owned())]
            );
            // Both counters seeded past the global max (2): no id is reused.
            db.insert_nvme_export(&new("vm2")).unwrap()
        };
        assert_eq!(new_id, 3, "next nvme id continues past the legacy max");

        // The rewritten file is in the two-table shape; the legacy fields are gone.
        let text = std::fs::read_to_string(&state).unwrap();
        assert!(
            !text.contains("[[export]]") && !text.contains("kind ="),
            "legacy table must be rewritten away: {text}"
        );
        assert!(
            text.contains("[[nvme_export]]") && text.contains("[[iscsi_export]]"),
            "{text}"
        );
        // Re-open is a no-op migration: data is stable.
        {
            let db = Db::open(&tasks_db, &state).unwrap();
            assert_eq!(db.list_nvme_exports().unwrap().len(), 2);
            assert_eq!(db.list_iscsi_exports().unwrap().len(), 1);
        }

        for ext in ["db", "db-wal", "db-shm"] {
            std::fs::remove_file(dir.join(format!("gd-mig-tasks{tag}.{ext}"))).ok();
        }
        std::fs::remove_file(&state).ok();
    }
}
