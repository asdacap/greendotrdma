//! Wire protocol between greendot-web (unprivileged) and greendot-helper (root).
//!
//! Every request variant is one allowlisted privileged operation. All strings
//! that end up as path components or command arguments are validated newtypes;
//! validation runs on construction *and* on deserialization, so the helper
//! re-validates everything it receives by merely decoding it.

mod types;
mod validate;
pub mod wire;

pub use types::*;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

    // NVMe-oF target (nvmet configfs)
    NvmetSubsysCreate {
        nqn: Nqn,
        allow_any_host: bool,
    },
    NvmetSubsysDelete {
        nqn: Nqn,
    },
    NvmetNamespaceSet {
        nqn: Nqn,
        nsid: u32,
        device_path: DevicePath,
        enable: bool,
    },
    NvmetNamespaceDelete {
        nqn: Nqn,
        nsid: u32,
    },
    NvmetPortCreate {
        id: u16,
        trtype: Transport,
        traddr: IpAddr,
        trsvcid: u16,
    },
    NvmetPortDelete {
        id: u16,
    },
    NvmetPortLink {
        port: u16,
        nqn: Nqn,
    },
    NvmetPortUnlink {
        port: u16,
        nqn: Nqn,
    },
    NvmetHostAllow {
        nqn: Nqn,
        host_nqn: Nqn,
    },
    NvmetHostRemove {
        nqn: Nqn,
        host_nqn: Nqn,
    },

    // iSCSI target (LIO configfs)
    LioBackstoreCreate {
        name: BackstoreName,
        device_path: DevicePath,
    },
    LioBackstoreDelete {
        name: BackstoreName,
    },
    LioTargetCreate {
        iqn: Iqn,
    },
    LioTargetDelete {
        iqn: Iqn,
    },
    LioLunMap {
        iqn: Iqn,
        lun: u32,
        backstore: BackstoreName,
    },
    LioPortalSet {
        iqn: Iqn,
        addr: IpAddr,
        port: u16,
        iser: bool,
    },
    LioPortalDelete {
        iqn: Iqn,
        addr: IpAddr,
        port: u16,
    },
    LioAclAdd {
        iqn: Iqn,
        initiator: Iqn,
    },
    LioAclRemove {
        iqn: Iqn,
        initiator: Iqn,
    },
    LioTpgSet {
        iqn: Iqn,
        enabled: bool,
        demo_mode: bool,
        auth: Option<ChapCreds>,
    },

    // System
    EnsureModules {
        modules: Vec<KernelModule>,
    },
    RxeLinkAdd {
        netdev: NetdevName,
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
    #[case::port(Request::NvmetPortCreate {
        id: 1,
        trtype: Transport::Rdma,
        traddr: "192.168.1.10".parse().unwrap(),
        trsvcid: 4420,
    })]
    #[case::portal(Request::LioPortalSet {
        iqn: Iqn::new("iqn.2026-06.io.greendot:vm1").unwrap(),
        addr: "::1".parse().unwrap(),
        port: 3260,
        iser: true,
    })]
    #[case::modules(Request::EnsureModules {
        modules: vec![KernelModule::NvmetRdma, KernelModule::Rxe],
    })]
    fn request_roundtrips(#[case] req: Request) {
        assert_eq!(roundtrip(&req), req);
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
            r#"{"op":"nvmet_subsys_delete","nqn":"not-an-nqn"}"#,
            r#"{"op":"rxe_link_add","netdev":"eth0/../x"}"#,
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
