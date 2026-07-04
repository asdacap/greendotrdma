//! Protocol between greendot-web (unprivileged) and greendotctl (root).
//!
//! This module holds the *validated domain model* — `Request`/`Response`/
//! `TaskEvent` and the newtypes in `types`. Every request variant is one
//! allowlisted privileged operation, and all strings that end up as path
//! components or command arguments are validated newtypes.
//!
//! The transport is gRPC (tonic): the generated protobuf types live in [`pb`],
//! and [`convert`] provides the conversions. Crucially, protobuf messages are
//! plain strings that prost does *not* validate on decode, so the daemon must
//! convert every incoming `pb::Request` via `TryFrom` (in `convert`), which
//! re-runs the validators — that conversion is the security choke point the
//! serde `Deserialize` impls used to provide for free.

pub mod client;
mod convert;
mod osdetect;
mod types;
mod validate;

/// Generated protobuf/gRPC transport types. Kept separate from the validated
/// domain model (`Request`/`Response`/`TaskEvent` below); see `convert` for the
/// validating conversions between the two.
pub mod pb {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]
    tonic::include_proto!("greendot.helper.v1");
}

pub use convert::ConvertError;
pub use osdetect::*;
pub use types::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Authenticate {
        username: Username,
        password: Secret,
    },

    // ZFS (reads happen unprivileged in greendot-web)
    ZvolCreate {
        dataset: DatasetName,
        size: u64,
        volblocksize: Option<u32>,
        sparse: bool,
    },
    ZvolDelete {
        dataset: DatasetName,
    },
    ZvolResize {
        dataset: DatasetName,
        new_size: u64,
    },
    SnapshotCreate {
        dataset: DatasetName,
        snap: SnapName,
    },
    SnapshotDestroy {
        dataset: DatasetName,
        snap: SnapName,
    },

    // ZFS filesystem datasets (mount lifecycle). Reads happen unprivileged in
    // greendot-web; these mutations are imperative one-shots (no desired state).
    ZfsFsCreate {
        dataset: DatasetName,
        /// `None` inherits the default `<pool>/<path>` mountpoint.
        mountpoint: Option<MountPoint>,
    },
    ZfsSetMountpoint {
        dataset: DatasetName,
        mountpoint: MountPoint,
    },
    ZfsMount {
        dataset: DatasetName,
    },
    ZfsUnmount {
        dataset: DatasetName,
    },
    ZfsDestroy {
        dataset: DatasetName,
        recursive: bool,
    },

    // Partitioning (sfdisk)
    PartitionTableCreate {
        disk: BlockDev,
    },
    PartitionCreate {
        disk: BlockDev,
        start_sector: Option<u64>,
        size_sectors: Option<u64>,
        label: PartLabel,
    },
    PartitionDelete {
        disk: BlockDev,
        number: u32,
    },
    /// Shrink a partition in place (start sector preserved). The web side runs
    /// the filesystem shrink first, then this.
    PartitionResize {
        disk: BlockDev,
        number: u32,
        size_sectors: u64,
    },

    // Filesystem shrink steps (each one CLI command; the web side sequences
    // them, filesystem always before the partition).
    Fsck {
        device: DevicePath,
    },
    ResizeExt {
        device: DevicePath,
        new_size_sectors: u64,
    },
    BtrfsMount {
        device: DevicePath,
        mount_path: MountPath,
    },
    BtrfsResize {
        mount_path: MountPath,
        new_size: u64,
    },
    Umount {
        mount_path: MountPath,
    },

    // ZFS pools (zvol ops are above; reads happen unprivileged in greendot-web)
    PoolCreate {
        name: PoolName,
        vdev: VdevLayout,
        devices: Vec<DevicePath>,
        ashift: Option<u8>,
    },
    PoolDeviceAdd {
        pool: PoolName,
        device: DevicePath,
    },

    // SMART (privileged reads via smartctl, which needs root). The full report
    // is a plain task the web collects (not recorded on the Tasks page); the
    // batch health read is a special arm that merges per-device JSON, like
    // RoceCapableNics. The web prepends `/dev/` to the validated bare name.
    /// Full `smartctl -x` dump for one device, collected verbatim by the web.
    SmartReport {
        device: BlockDev,
    },
    /// Per-device SMART health + temperature for a batch of devices, streamed as
    /// `[{device, passed, temp_c}]` JSON — the dots/temps on the list.
    SmartHealth {
        devices: Vec<BlockDev>,
    },

    // LVM. Reads need root, so they go through the helper too (LvmReport),
    // unlike ZFS reads which the web service runs unprivileged.
    LvmReport {
        what: LvmReport,
    },
    VgCreate {
        name: VgName,
        devices: Vec<DevicePath>,
    },
    VgExtend {
        vg: VgName,
        device: DevicePath,
    },
    VgReduce {
        vg: VgName,
        device: DevicePath,
    },
    VgRemove {
        vg: VgName,
    },
    LvCreate {
        vg: VgName,
        name: LvName,
        size: u64,
    },
    ThinPoolCreate {
        vg: VgName,
        name: LvName,
        size: u64,
    },
    ThinLvCreate {
        vg: VgName,
        pool: LvName,
        name: LvName,
        virtual_size: u64,
    },
    /// Grow a logical volume (`lvextend`).
    LvResize {
        vg: VgName,
        name: LvName,
        new_size: u64,
    },
    /// Shrink a logical volume (`lvreduce -f`; destructive).
    LvShrink {
        vg: VgName,
        name: LvName,
        new_size: u64,
    },
    LvRename {
        vg: VgName,
        name: LvName,
        new_name: LvName,
    },
    LvDelete {
        vg: VgName,
        name: LvName,
    },

    // NVMe-oF / iSCSI targets: the helper applies NvmetDesired directly to
    // configfs, and renders LioDesired to targetctl JSON (restore command).
    NvmetApply {
        desired: NvmetDesired,
    },
    LioApply {
        desired: LioDesired,
    },
    // NFS: the helper writes our exports file directly, applies it surgically
    // with `exportfs -o`/`-u`, and asserts the nfsd RDMA listener.
    NfsApply {
        desired: NfsDesired,
    },
    /// Privileged read of NFS actual state (`exportfs -s` + `/proc/fs/nfsd/portlist`),
    /// which the unprivileged web service cannot read directly.
    NfsReport,

    // System
    EnsureModules {
        modules: Vec<KernelModule>,
    },
    RxeLinkAdd {
        netdev: NetdevName,
    },
    /// Inventory of RoCE-capable NIC hardware (a privileged read): the helper
    /// classifies vendors via its `NetworkHardware` registry and returns
    /// `[{netdev, vendor}]` JSON. The web overlays this onto its structural NIC
    /// classification — it carries no vendor knowledge itself.
    RoceCapableNics,
    /// Turn on hardware RoCE for `netdev`. The helper detects the vendor, probes
    /// its enable parameter, and (only if present and off) sets it and reloads
    /// the device — the whole vendor-specific flow lives behind the helper.
    EnableRoce {
        netdev: NetdevName,
    },
    /// Per-NIC RDMA *advisories* (a privileged read): the helper inspects each
    /// NIC's hardware via its vendor knowledge and returns opaque
    /// `[{netdev, label, detail}]` JSON explaining why a NIC may lack RDMA and
    /// how to fix it (e.g. an SR-IOV VF whose host must load the RDMA driver
    /// before setting the VF count). The web renders these verbatim on the
    /// per-NIC Diagnose page — it carries no vendor knowledge itself.
    NicRdmaAdvice,
    /// Read live RDMA connections (`rdma -j resource show cm_id`): a privileged
    /// *read* used to surface NVMe-oF/iSER peers the kernel exposes no other
    /// way (this kernel lacks CONFIG_NVME_TARGET_DEBUGFS).
    RdmaResources,
    InstallPackages {
        packages: Vec<PackageName>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok,
    OkAuth { username: String },
    Err { kind: ErrKind, message: String },
}

impl Response {
    pub fn err(kind: ErrKind, message: impl Into<String>) -> Self {
        Response::Err {
            kind,
            message: message.into(),
        }
    }
}

/// Receives task events as they happen — the socket writer in the daemon, a
/// stdout writer in the standalone CLI, or a collector in tests. Returning `Err`
/// aborts streaming. Lives here, next to [`TaskEvent`], so both the helper's
/// apply functions and the transport-agnostic reconciler can name one trait.
pub trait EventSink {
    fn emit(&mut self, ev: TaskEvent) -> std::io::Result<()>;
}

/// A typed handle over an [`EventSink`] that structures a run as a task of one
/// or more sequential [`SubTask`]s, each with its own recorded output and
/// terminal [`SubStatus`]. This is a thin layer *on top of* `emit(TaskEvent)` —
/// the sink stays the transport; `Task`/`SubTask`/`Pipe` just guarantee the
/// framing invariants (every task ends with exactly one `Finished` whose status
/// is the worst child; output attributes to the open subtask).
///
/// ```ignore
/// let mut task = Task::new(sink);
/// let mut sub = task.begin_subtask("Load kernel modules");
/// writeln!(sub.stdout(), "$ modprobe nvmet_rdma")?;
/// sub.complete(SubStatus::Success);
/// task.complete()?;
/// ```
///
/// The mutable borrow taken by `begin_*` *is* the sequential guarantee: the
/// previous subtask must drop (finish) before the next one can open.
pub struct Task<'s> {
    sink: &'s mut dyn EventSink,
    /// Folded status of every finished subtask so far (`None` until the first).
    agg: Option<SubStatus>,
    /// First failing subtask's error message — becomes the task-level `error`.
    first_err: Option<String>,
    /// A sink error captured on a path that can't return `io::Result`
    /// (`begin_*`, subtask `Drop`); surfaced by the next `Pipe::write` /
    /// `complete`, preserving "stop streaming the instant the client hangs up".
    pending: Option<std::io::Error>,
}

impl<'s> Task<'s> {
    pub fn new(sink: &'s mut dyn EventSink) -> Self {
        Task {
            sink,
            agg: None,
            first_err: None,
            pending: None,
        }
    }

    /// Open a plain subtask (a human label, no command header). Output written
    /// to its pipes belongs to it until it finishes.
    pub fn begin_subtask(&mut self, name: impl Into<String>) -> SubTask<'_, 's> {
        self.emit_soft(TaskEvent::SubtaskStarted {
            name: name.into(),
            command: None,
            args: Vec::new(),
            stdin: None,
        });
        SubTask::new(self)
    }

    /// Open a subtask that wraps a single process, carrying the `$ cmd` header
    /// fields (`command`/`args`/`stdin`).
    pub fn begin_command(
        &mut self,
        name: impl Into<String>,
        command: impl Into<String>,
        args: Vec<String>,
        stdin: Option<String>,
    ) -> SubTask<'_, 's> {
        self.emit_soft(TaskEvent::SubtaskStarted {
            name: name.into(),
            command: Some(command.into()),
            args,
            stdin,
        });
        SubTask::new(self)
    }

    /// Record an already-satisfied step as a grey `Skipped` dot (opened and
    /// closed with no output).
    pub fn skipped_subtask(&mut self, name: impl Into<String>) {
        self.emit_soft(TaskEvent::SubtaskStarted {
            name: name.into(),
            command: None,
            args: Vec::new(),
            stdin: None,
        });
        self.finish_subtask(SubStatus::Skipped, 0, None);
    }

    /// The worst subtask status seen so far (`Success` if no subtask ran).
    pub fn aggregate(&self) -> SubStatus {
        self.agg.unwrap_or(SubStatus::Success)
    }

    /// Emit the single terminal `Finished` (status = worst child, error = first
    /// failing subtask's message), consuming the task. Surfaces any deferred
    /// sink error first.
    pub fn complete(mut self) -> std::io::Result<()> {
        let status = self.aggregate();
        let error = self.first_err.take();
        self.take_pending()?;
        self.emit(TaskEvent::Finished { status, error })
    }

    /// Close the current subtask: fold its status, remember the first error, and
    /// emit `SubtaskFinished`. Called by `SubTask::complete`/`fail`/`Drop` and by
    /// `skipped_subtask`.
    fn finish_subtask(&mut self, status: SubStatus, exit: i32, error: Option<String>) {
        self.agg = Some(SubStatus::fold(self.agg, status));
        if status == SubStatus::Failed && self.first_err.is_none() {
            self.first_err = error.clone();
        }
        self.emit_soft(TaskEvent::SubtaskFinished {
            status,
            exit,
            error,
        });
    }

    /// Hard emit — the error propagates to the caller (via `Pipe::write`/
    /// `complete`).
    fn emit(&mut self, ev: TaskEvent) -> std::io::Result<()> {
        self.sink.emit(ev)
    }

    /// Soft emit — used where we can't return `io::Result`. The first sink error
    /// is stashed in `pending`; later frames are skipped (client is gone).
    fn emit_soft(&mut self, ev: TaskEvent) {
        if self.pending.is_none()
            && let Err(e) = self.sink.emit(ev)
        {
            self.pending = Some(e);
        }
    }

    fn take_pending(&mut self) -> std::io::Result<()> {
        match self.pending.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// A single step of a [`Task`], holding a mutable borrow of it (so the next
/// subtask can't open until this one finishes). Its `stdout()`/`stderr()` pipes
/// stream output attributed to this subtask. Failures are reported via
/// `complete(Failed)`/`fail(...)` — never via `?` (a `?` fires only on a sink
/// error, i.e. the client is gone, where the terminal status is moot). `Drop`
/// auto-completes as `Success`.
pub struct SubTask<'t, 's> {
    task: &'t mut Task<'s>,
    exit: i32,
    error: Option<String>,
    done: bool,
}

impl<'t, 's> SubTask<'t, 's> {
    fn new(task: &'t mut Task<'s>) -> Self {
        SubTask {
            task,
            exit: 0,
            error: None,
            done: false,
        }
    }

    /// A writer whose every `write` emits one `Stdout` event for this subtask.
    pub fn stdout(&mut self) -> Pipe<'_, 's> {
        Pipe {
            task: self.task,
            stderr: false,
        }
    }

    /// A writer whose every `write` emits one `Stderr` event for this subtask.
    pub fn stderr(&mut self) -> Pipe<'_, 's> {
        Pipe {
            task: self.task,
            stderr: true,
        }
    }

    /// Record the wrapped process's exit code and (optional) error message, to be
    /// carried on this subtask's `SubtaskFinished`.
    pub fn set_result(&mut self, exit: i32, error: Option<String>) {
        self.exit = exit;
        self.error = error;
    }

    /// Finish this subtask with an explicit status.
    pub fn complete(mut self, status: SubStatus) {
        self.finish(status);
    }

    /// Finish this subtask as `Failed` with a human message.
    pub fn fail(mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.finish(SubStatus::Failed);
    }

    fn finish(&mut self, status: SubStatus) {
        if self.done {
            return;
        }
        self.done = true;
        let error = self.error.take();
        self.task.finish_subtask(status, self.exit, error);
    }
}

impl Drop for SubTask<'_, '_> {
    fn drop(&mut self) {
        self.finish(SubStatus::Success);
    }
}

/// An `io::Write` that turns each `write` into one `Stdout`/`Stderr` event on the
/// underlying task (no buffering; `flush` is a no-op). Deferred sink errors
/// surface here so streaming stops the instant the client hangs up.
pub struct Pipe<'p, 's> {
    task: &'p mut Task<'s>,
    stderr: bool,
}

impl std::io::Write for Pipe<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.task.take_pending()?;
        let data = String::from_utf8_lossy(buf).into_owned();
        let ev = if self.stderr {
            TaskEvent::Stderr { data }
        } else {
            TaskEvent::Stdout { data }
        };
        self.task.emit(ev)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrKind {
    AuthFailed,
    NotInAdminGroup,
    Validation,
    Busy,
    Sys,
    CmdFailed,
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn roundtrip(req: &Request) -> Request {
        let json = serde_json::to_string(req).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[rstest]
    #[case::ping(Request::Ping)]
    #[case::auth(Request::Authenticate {
        username: Username::new("alice").unwrap(),
        password: Secret("hunter2".into()),
    })]
    #[case::zvol(Request::ZvolCreate {
        dataset: DatasetName::new("tank/vols/vm1").unwrap(),
        size: 10 << 30,
        volblocksize: Some(16384),
        sparse: true,
    })]
    #[case::nvmet(Request::NvmetApply {
        desired: NvmetDesired {
            subsystems: vec![NvmetSubsysSpec {
                nqn: Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap(),
                allow_any_host: false,
                allowed_hosts: vec![Nqn::new("nqn.2014-08.org.nvmexpress:host1").unwrap()],
                namespaces: vec![NvmetNsSpec {
                    nsid: 1,
                    device_path: DevicePath::new("/dev/zvol/tank/vm1").unwrap(),
                }],
            }],
            ports: vec![NvmetPortSpec {
                id: 1,
                trtype: Transport::Rdma,
                traddr: "192.168.1.10".parse().unwrap(),
                trsvcid: 4420,
                subsystems: vec![Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap()],
            }],
        },
    })]
    #[case::lio(Request::LioApply {
        desired: LioDesired {
            backstores: vec![LioBackstoreSpec {
                name: BackstoreName::new("vm1").unwrap(),
                device_path: DevicePath::new("/dev/zvol/tank/vm1").unwrap(),
            }],
            targets: vec![LioTargetSpec {
                iqn: Iqn::new("iqn.2026-06.io.greendot:vm1").unwrap(),
                enabled: true,
                demo_mode: false,
                luns: vec![LioLunSpec { lun: 0, backstore: BackstoreName::new("vm1").unwrap() }],
                portals: vec![LioPortalSpec { addr: "::1".parse().unwrap(), port: 3260, iser: true }],
                acls: vec![Iqn::new("iqn.1993-08.org.debian:01:abc").unwrap()],
            }],
        },
    })]
    #[case::part_resize(Request::PartitionResize {
        disk: BlockDev::new("sdb").unwrap(),
        number: 2,
        size_sectors: 2097152,
    })]
    #[case::resize_ext(Request::ResizeExt {
        device: DevicePath::new("/dev/sdb2").unwrap(),
        new_size_sectors: 2097152,
    })]
    #[case::btrfs_resize(Request::BtrfsResize {
        mount_path: MountPath::new("/run/greendotrdma/btrfs-resize-sdb2").unwrap(),
        new_size: 1 << 30,
    })]
    #[case::pool_create(Request::PoolCreate {
        name: PoolName::new("tank").unwrap(),
        vdev: VdevLayout::Mirror,
        devices: vec![
            DevicePath::new("/dev/sdb").unwrap(),
            DevicePath::new("/dev/sdc").unwrap(),
        ],
        ashift: Some(12),
    })]
    #[case::pool_add(Request::PoolDeviceAdd {
        pool: PoolName::new("tank").unwrap(),
        device: DevicePath::new("/dev/sdd").unwrap(),
    })]
    #[case::smart_report(Request::SmartReport { device: BlockDev::new("sda").unwrap() })]
    #[case::smart_health(Request::SmartHealth {
        devices: vec![BlockDev::new("sda").unwrap(), BlockDev::new("nvme0n1").unwrap()],
    })]
    #[case::lvm_report(Request::LvmReport { what: LvmReport::Lvs })]
    #[case::vg_create(Request::VgCreate {
        name: VgName::new("vg0").unwrap(),
        devices: vec![
            DevicePath::new("/dev/sdb").unwrap(),
            DevicePath::new("/dev/sdc").unwrap(),
        ],
    })]
    #[case::thin_lv(Request::ThinLvCreate {
        vg: VgName::new("vg0").unwrap(),
        pool: LvName::new("pool0").unwrap(),
        name: LvName::new("vm1").unwrap(),
        virtual_size: 20 << 30,
    })]
    #[case::lv_rename(Request::LvRename {
        vg: VgName::new("vg0").unwrap(),
        name: LvName::new("old").unwrap(),
        new_name: LvName::new("new").unwrap(),
    })]
    #[case::modules(Request::EnsureModules {
        modules: vec![KernelModule::NvmetRdma, KernelModule::Rxe],
    })]
    #[case::roce_capable_nics(Request::RoceCapableNics)]
    #[case::enable_roce(Request::EnableRoce {
        netdev: NetdevName::new("ens16").unwrap(),
    })]
    #[case::nic_rdma_advice(Request::NicRdmaAdvice)]
    #[case::rdma_resources(Request::RdmaResources)]
    #[case::install(Request::InstallPackages {
        packages: vec![PackageName::new("nvme-cli").unwrap(), PackageName::new("targetcli-fb").unwrap()],
    })]
    #[case::zfs_fs_create(Request::ZfsFsCreate {
        dataset: DatasetName::new("tank/share").unwrap(),
        mountpoint: Some(MountPoint::new("/tank/share").unwrap()),
    })]
    #[case::zfs_fs_create_default(Request::ZfsFsCreate {
        dataset: DatasetName::new("tank/share").unwrap(),
        mountpoint: None,
    })]
    #[case::zfs_set_mountpoint(Request::ZfsSetMountpoint {
        dataset: DatasetName::new("tank/share").unwrap(),
        mountpoint: MountPoint::new("/srv/share").unwrap(),
    })]
    #[case::zfs_mount(Request::ZfsMount { dataset: DatasetName::new("tank/share").unwrap() })]
    #[case::zfs_unmount(Request::ZfsUnmount { dataset: DatasetName::new("tank/share").unwrap() })]
    #[case::zfs_destroy(Request::ZfsDestroy { dataset: DatasetName::new("tank/share").unwrap(), recursive: true })]
    #[case::nfs_apply(Request::NfsApply {
        desired: NfsDesired {
            rdma_port: NFS_RDMA_PORT,
            exports: vec![NfsExportSpec {
                path: NfsExportPath::new("/tank/share").unwrap(),
                fsid: 0x6700_0001,
                clients: vec![NfsClientSpec {
                    client: NfsClient::new("192.168.101.0/24").unwrap(),
                    rw: true,
                }],
            }],
        },
    })]
    #[case::nfs_report(Request::NfsReport)]
    fn request_roundtrips(#[case] req: Request) {
        assert_eq!(roundtrip(&req), req);
    }

    #[test]
    fn task_events_roundtrip() {
        for ev in [
            TaskEvent::SubtaskStarted {
                name: "Apply NVMe-oF".into(),
                command: Some("configfs".into()),
                args: vec!["nvmet".into(), "apply".into()],
                stdin: Some("{}".into()),
            },
            TaskEvent::SubtaskStarted {
                name: "Load kernel modules".into(),
                command: None,
                args: vec![],
                stdin: None,
            },
            TaskEvent::Stdout {
                data: "hello\n".into(),
            },
            TaskEvent::Stderr {
                data: "warn\n".into(),
            },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Failed,
                exit: 1,
                error: Some("boom".into()),
            },
            TaskEvent::Finished {
                status: SubStatus::Success,
                error: None,
            },
        ] {
            let json = serde_json::to_string(&ev).unwrap();
            assert_eq!(serde_json::from_str::<TaskEvent>(&json).unwrap(), ev);
        }
        // Serde tags are the wire contract the JSONL reconcile stream relies on.
        assert_eq!(
            serde_json::to_string(&TaskEvent::Finished {
                status: SubStatus::Skipped,
                error: None,
            })
            .unwrap(),
            r#"{"ev":"finished","status":"skipped","error":null}"#
        );
    }

    #[rstest]
    // Failed dominates regardless of order or accumulator.
    #[case(None, SubStatus::Failed, SubStatus::Failed)]
    #[case(Some(SubStatus::Success), SubStatus::Failed, SubStatus::Failed)]
    #[case(Some(SubStatus::Failed), SubStatus::Success, SubStatus::Failed)]
    // Success beats Skipped in both directions (not a plain max).
    #[case(Some(SubStatus::Skipped), SubStatus::Success, SubStatus::Success)]
    #[case(Some(SubStatus::Success), SubStatus::Skipped, SubStatus::Success)]
    // All-skipped stays skipped.
    #[case(None, SubStatus::Skipped, SubStatus::Skipped)]
    #[case(Some(SubStatus::Skipped), SubStatus::Skipped, SubStatus::Skipped)]
    fn substatus_fold(
        #[case] acc: Option<SubStatus>,
        #[case] s: SubStatus,
        #[case] expected: SubStatus,
    ) {
        assert_eq!(SubStatus::fold(acc, s), expected);
    }

    #[test]
    fn responses_roundtrip_and_invalid_payloads_are_rejected_on_decode() {
        for resp in [
            Response::Ok,
            Response::OkAuth {
                username: "alice".into(),
            },
            Response::err(ErrKind::CmdFailed, "zfs exited 1: boom"),
        ] {
            let json = serde_json::to_string(&resp).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), resp);
        }
        // Deserialization must enforce validation (the helper's second line of defense).
        for bad in [
            r#"{"op":"zvol_delete","dataset":"../../etc"}"#,
            r#"{"op":"rxe_link_add","netdev":"eth0/../x"}"#,
            r#"{"op":"install_packages","packages":["foo;rm -rf"]}"#,
            r#"{"op":"pool_create","name":"mirror","vdev":"stripe","devices":["/dev/sdb"],"ashift":null}"#,
            r#"{"op":"lv_delete","vg":"vg0","name":"../x"}"#,
            r#"{"op":"vg_create","name":"-bad","devices":["/dev/sdb"]}"#,
            r#"{"op":"btrfs_resize","mount_path":"/run/greendotrdma/btrfs-resize-../etc","new_size":1024}"#,
            r#"{"op":"enable_roce","netdev":"eth0 ; reboot"}"#,
            r#"{"op":"zfs_mount","dataset":"../../etc"}"#,
            r#"{"op":"zfs_set_mountpoint","dataset":"tank/share","mountpoint":"/tank/../etc"}"#,
            r#"{"op":"nfs_apply","desired":{"rdma_port":20049,"exports":[{"path":"/tank/../etc","fsid":1,"clients":[]}]}}"#,
            r#"{"op":"nfs_apply","desired":{"rdma_port":20049,"exports":[{"path":"/srv","fsid":1,"clients":[{"client":"h(rw","rw":true}]}]}}"#,
            r#"{"op":"no_such_op"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let req = Request::Authenticate {
            username: Username::new("alice").unwrap(),
            password: Secret("hunter2".into()),
        };
        assert!(!format!("{req:?}").contains("hunter2"));
    }
}
