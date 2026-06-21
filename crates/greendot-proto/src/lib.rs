//! Wire protocol between greendot-web (unprivileged) and greendot-helper (root).
//!
//! Every request variant is one allowlisted privileged operation. All strings
//! that end up as path components or command arguments are validated newtypes;
//! validation runs on construction *and* on deserialization, so the helper
//! re-validates everything it receives by merely decoding it.

mod osdetect;
mod types;
mod validate;
pub mod wire;

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

    // System
    EnsureModules {
        modules: Vec<KernelModule>,
    },
    RxeLinkAdd {
        netdev: NetdevName,
    },
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
    #[case::install(Request::InstallPackages {
        packages: vec![PackageName::new("nvme-cli").unwrap(), PackageName::new("targetcli-fb").unwrap()],
    })]
    fn request_roundtrips(#[case] req: Request) {
        assert_eq!(roundtrip(&req), req);
    }

    #[test]
    fn task_events_roundtrip() {
        for ev in [
            TaskEvent::Started {
                command: "configfs".into(),
                args: vec!["nvmet".into(), "apply".into()],
                stdin: Some("{}".into()),
            },
            TaskEvent::Stdout {
                data: "hello\n".into(),
            },
            TaskEvent::Stderr {
                data: "warn\n".into(),
            },
            TaskEvent::Finished {
                exit: 0,
                ok: true,
                error: None,
            },
        ] {
            let json = serde_json::to_string(&ev).unwrap();
            assert_eq!(serde_json::from_str::<TaskEvent>(&json).unwrap(), ev);
        }
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
