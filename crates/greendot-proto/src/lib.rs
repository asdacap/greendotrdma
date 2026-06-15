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

    // NVMe-oF / iSCSI targets: the helper renders these to nvmetcli /
    // targetctl JSON and applies them with the tools' restore command.
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
    #[case::modules(Request::EnsureModules {
        modules: vec![KernelModule::NvmetRdma, KernelModule::Rxe],
    })]
    #[case::install(Request::InstallPackages {
        packages: vec![PackageName::new("nvmetcli").unwrap(), PackageName::new("targetcli-fb").unwrap()],
    })]
    fn request_roundtrips(#[case] req: Request) {
        assert_eq!(roundtrip(&req), req);
    }

    #[test]
    fn task_events_roundtrip() {
        for ev in [
            TaskEvent::Started {
                command: "nvmetcli".into(),
                args: vec!["restore".into(), "/dev/stdin".into()],
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
