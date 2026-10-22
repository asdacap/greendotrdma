//! Conversions between the generated protobuf transport types (`crate::pb`)
//! and the validated domain model: the shared enums, the desired-state spec
//! documents, the typed read replies (mirroring the `actual::*` DTOs), the
//! auth reply, and the task event stream. The per-op request conversions live
//! in [`crate::ops`], one `TryFrom` per rpc.
//!
//! Direction matters for security:
//! - **`From<domain> for pb::…`** (client egress) is infallible: domain values
//!   are already valid, so we just unwrap them into plain strings/ints.
//! - **`TryFrom<pb::…> for domain`** (server ingress) re-runs every validator.
//!   Reply ingress (daemon → web) is deliberately *lossy-graceful* instead:
//!   unparseable addresses drop out, mirroring the web's degrade-to-empty
//!   handling of read failures.

use crate::pb;
use crate::{
    AuthResult, BackstoreName, BlockDev, Compression, DatasetName, DevicePath, ErrKind, Iqn,
    LioBackstoreSpec, LioDesired, LioLunSpec, LioPortalSpec, LioTargetSpec, LogBias, LvmReport,
    NfsClient, NfsClientSpec, NfsDesired, NfsExportPath, NfsExportSpec, Nqn, NvmetDesired,
    NvmetNsSpec, NvmetPortSpec, NvmetSubsysSpec, PackageName, PciAddress, PrimaryCache, SubStatus,
    TaskEvent, Transport, ValidationError, VdevClass, VdevLayout, VolMode, ZvolSync, actual,
};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

/// A failure converting a decoded protobuf message into the validated domain
/// model. On the server this maps to a failed task / an INVALID_ARGUMENT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConvertError {}

impl From<ValidationError> for ConvertError {
    fn from(e: ValidationError) -> Self {
        ConvertError(e.to_string())
    }
}

// ---- small helpers (shared with `ops`) ----

pub(crate) fn to_u16(v: u32, what: &str) -> Result<u16, ConvertError> {
    u16::try_from(v).map_err(|_| ConvertError(format!("{what} out of u16 range: {v}")))
}

pub(crate) fn to_u8(v: u32, what: &str) -> Result<u8, ConvertError> {
    u8::try_from(v).map_err(|_| ConvertError(format!("{what} out of u8 range: {v}")))
}

pub(crate) fn parse_ip(s: &str) -> Result<IpAddr, ConvertError> {
    s.parse()
        .map_err(|_| ConvertError(format!("invalid IP address: {s:?}")))
}

/// Validate a `Vec<String>` into a `Vec<newtype>` using the newtype constructor.
pub(crate) fn map_new<T, F>(v: Vec<String>, f: F) -> Result<Vec<T>, ConvertError>
where
    F: Fn(String) -> Result<T, ValidationError>,
{
    v.into_iter()
        .map(|s| f(s).map_err(ConvertError::from))
        .collect()
}

/// Validate a `Vec<pb::Spec>` into a `Vec<domain::Spec>` via `TryFrom`.
fn map_try<P, T>(v: Vec<P>) -> Result<Vec<T>, ConvertError>
where
    T: TryFrom<P, Error = ConvertError>,
{
    v.into_iter().map(T::try_from).collect()
}

/// Unwrap a `Vec<newtype>` into a `Vec<String>` (egress).
pub(crate) fn strs<T: AsRef<str>>(v: &[T]) -> Vec<String> {
    v.iter().map(|s| s.as_ref().to_owned()).collect()
}

/// Lossy-graceful reply ingress: parse each string, dropping failures.
fn parse_addrs(v: &[String]) -> Vec<IpAddr> {
    v.iter().filter_map(|s| s.parse().ok()).collect()
}

fn addr_strs(v: &[IpAddr]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

// The newtypes deref to `&str` via `as_str`; give them AsRef<str> so `strs`
// works uniformly.
macro_rules! as_ref_str {
    ($($t:ty),* $(,)?) => {$(
        impl AsRef<str> for $t {
            fn as_ref(&self) -> &str { self.as_str() }
        }
    )*};
}
as_ref_str!(DatasetName, DevicePath, Nqn, Iqn, BlockDev, PackageName);

// ---- enums ----

impl From<Transport> for pb::Transport {
    fn from(t: Transport) -> Self {
        match t {
            Transport::Rdma => pb::Transport::Rdma,
            Transport::Tcp => pb::Transport::Tcp,
            Transport::Loop => pb::Transport::Loop,
        }
    }
}
impl TryFrom<pb::Transport> for Transport {
    type Error = ConvertError;
    fn try_from(t: pb::Transport) -> Result<Self, ConvertError> {
        Ok(match t {
            pb::Transport::Rdma => Transport::Rdma,
            pb::Transport::Tcp => Transport::Tcp,
            pb::Transport::Loop => Transport::Loop,
            pb::Transport::Unspecified => {
                return Err(ConvertError("unspecified transport".into()));
            }
        })
    }
}

impl From<VdevLayout> for pb::VdevLayout {
    fn from(v: VdevLayout) -> Self {
        match v {
            VdevLayout::Stripe => pb::VdevLayout::Stripe,
            VdevLayout::Mirror => pb::VdevLayout::Mirror,
            VdevLayout::Raidz1 => pb::VdevLayout::Raidz1,
            VdevLayout::Raidz2 => pb::VdevLayout::Raidz2,
            VdevLayout::Raidz3 => pb::VdevLayout::Raidz3,
        }
    }
}
impl TryFrom<pb::VdevLayout> for VdevLayout {
    type Error = ConvertError;
    fn try_from(v: pb::VdevLayout) -> Result<Self, ConvertError> {
        Ok(match v {
            pb::VdevLayout::Stripe => VdevLayout::Stripe,
            pb::VdevLayout::Mirror => VdevLayout::Mirror,
            pb::VdevLayout::Raidz1 => VdevLayout::Raidz1,
            pb::VdevLayout::Raidz2 => VdevLayout::Raidz2,
            pb::VdevLayout::Raidz3 => VdevLayout::Raidz3,
            pb::VdevLayout::Unspecified => {
                return Err(ConvertError("unspecified vdev layout".into()));
            }
        })
    }
}

impl From<VdevClass> for pb::VdevClass {
    fn from(v: VdevClass) -> Self {
        match v {
            VdevClass::Data => pb::VdevClass::Data,
            VdevClass::Special => pb::VdevClass::Special,
            VdevClass::Log => pb::VdevClass::Log,
            VdevClass::Dedup => pb::VdevClass::Dedup,
            VdevClass::Cache => pb::VdevClass::Cache,
            VdevClass::Spare => pb::VdevClass::Spare,
        }
    }
}
impl TryFrom<pb::VdevClass> for VdevClass {
    type Error = ConvertError;
    fn try_from(v: pb::VdevClass) -> Result<Self, ConvertError> {
        Ok(match v {
            pb::VdevClass::Data => VdevClass::Data,
            pb::VdevClass::Special => VdevClass::Special,
            pb::VdevClass::Log => VdevClass::Log,
            pb::VdevClass::Dedup => VdevClass::Dedup,
            pb::VdevClass::Cache => VdevClass::Cache,
            pb::VdevClass::Spare => VdevClass::Spare,
            pb::VdevClass::Unspecified => {
                return Err(ConvertError("unspecified vdev class".into()));
            }
        })
    }
}

impl From<LvmReport> for pb::LvmReportKind {
    fn from(r: LvmReport) -> Self {
        match r {
            LvmReport::Vgs => pb::LvmReportKind::Vgs,
            LvmReport::Lvs => pb::LvmReportKind::Lvs,
            LvmReport::Pvs => pb::LvmReportKind::Pvs,
        }
    }
}
impl TryFrom<pb::LvmReportKind> for LvmReport {
    type Error = ConvertError;
    fn try_from(r: pb::LvmReportKind) -> Result<Self, ConvertError> {
        Ok(match r {
            pb::LvmReportKind::Vgs => LvmReport::Vgs,
            pb::LvmReportKind::Lvs => LvmReport::Lvs,
            pb::LvmReportKind::Pvs => LvmReport::Pvs,
            pb::LvmReportKind::Unspecified => {
                return Err(ConvertError("unspecified lvm report".into()));
            }
        })
    }
}

impl From<ErrKind> for pb::ErrKind {
    fn from(k: ErrKind) -> Self {
        match k {
            ErrKind::AuthFailed => pb::ErrKind::AuthFailed,
            ErrKind::NotInAdminGroup => pb::ErrKind::NotInAdminGroup,
            ErrKind::Validation => pb::ErrKind::Validation,
            ErrKind::Busy => pb::ErrKind::Busy,
            ErrKind::Sys => pb::ErrKind::Sys,
            ErrKind::CmdFailed => pb::ErrKind::CmdFailed,
            ErrKind::Unsupported => pb::ErrKind::Unsupported,
        }
    }
}
impl TryFrom<pb::ErrKind> for ErrKind {
    type Error = ConvertError;
    fn try_from(k: pb::ErrKind) -> Result<Self, ConvertError> {
        Ok(match k {
            pb::ErrKind::AuthFailed => ErrKind::AuthFailed,
            pb::ErrKind::NotInAdminGroup => ErrKind::NotInAdminGroup,
            pb::ErrKind::Validation => ErrKind::Validation,
            pb::ErrKind::Busy => ErrKind::Busy,
            pb::ErrKind::Sys => ErrKind::Sys,
            pb::ErrKind::CmdFailed => ErrKind::CmdFailed,
            pb::ErrKind::Unsupported => ErrKind::Unsupported,
            pb::ErrKind::Unspecified => {
                return Err(ConvertError("unspecified error kind".into()));
            }
        })
    }
}

/// Decode a prost `i32` enumeration field into its domain enum, rejecting
/// values outside the schema.
/// Wire ↔ domain for the ZFS value enums (`types::zfs_value_enum!`). Variant
/// names match one-to-one; the `Unspecified` sentinel is rejected on ingress.
/// The `i32` impls let optional fields go through [`dec_opt`] / `map(i32::from)`.
macro_rules! zfs_value_pb {
    ($($name:ident { $($variant:ident),+ })*) => {$(
        impl From<$name> for pb::$name {
            fn from(v: $name) -> Self {
                match v { $($name::$variant => pb::$name::$variant),+ }
            }
        }
        impl From<$name> for i32 {
            fn from(v: $name) -> Self {
                pb::$name::from(v) as i32
            }
        }
        impl TryFrom<i32> for $name {
            type Error = ConvertError;
            fn try_from(i: i32) -> Result<Self, ConvertError> {
                let p = pb::$name::try_from(i)
                    .map_err(|_| ConvertError(format!("unknown {} {i}", $name::PROP)))?;
                Ok(match p {
                    $(pb::$name::$variant => $name::$variant,)+
                    pb::$name::Unspecified => {
                        return Err(ConvertError(format!("unspecified {}", $name::PROP)));
                    }
                })
            }
        }
    )*};
}
zfs_value_pb! {
    Compression { Off, Lz4, Zstd }
    ZvolSync { Standard, Always, Disabled }
    VolMode { Default, Full, Dev, None }
    PrimaryCache { All, Metadata, None }
    LogBias { Latency, Throughput }
}

/// An `optional` wire enum → an optional domain value (absent = inherit).
pub(crate) fn dec_opt<T: TryFrom<i32, Error = ConvertError>>(
    i: Option<i32>,
) -> Result<Option<T>, ConvertError> {
    i.map(T::try_from).transpose()
}

pub(crate) fn dec_transport(i: i32) -> Result<Transport, ConvertError> {
    let p =
        pb::Transport::try_from(i).map_err(|_| ConvertError(format!("unknown transport {i}")))?;
    Transport::try_from(p)
}

pub(crate) fn dec_vdev(i: i32) -> Result<VdevLayout, ConvertError> {
    let p = pb::VdevLayout::try_from(i)
        .map_err(|_| ConvertError(format!("unknown vdev layout {i}")))?;
    VdevLayout::try_from(p)
}

pub(crate) fn dec_vdev_class(i: i32) -> Result<VdevClass, ConvertError> {
    let p =
        pb::VdevClass::try_from(i).map_err(|_| ConvertError(format!("unknown vdev class {i}")))?;
    VdevClass::try_from(p)
}

pub(crate) fn dec_lvm_report(i: i32) -> Result<LvmReport, ConvertError> {
    let p = pb::LvmReportKind::try_from(i)
        .map_err(|_| ConvertError(format!("unknown lvm report {i}")))?;
    LvmReport::try_from(p)
}

// ---- desired-state nested structs ----

impl From<NvmetDesired> for pb::NvmetDesired {
    fn from(d: NvmetDesired) -> Self {
        pb::NvmetDesired {
            subsystems: d.subsystems.into_iter().map(Into::into).collect(),
            ports: d.ports.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::NvmetDesired> for NvmetDesired {
    type Error = ConvertError;
    fn try_from(d: pb::NvmetDesired) -> Result<Self, ConvertError> {
        Ok(NvmetDesired {
            subsystems: map_try(d.subsystems)?,
            ports: map_try(d.ports)?,
        })
    }
}

impl From<NvmetSubsysSpec> for pb::NvmetSubsysSpec {
    fn from(s: NvmetSubsysSpec) -> Self {
        pb::NvmetSubsysSpec {
            nqn: s.nqn.as_str().to_owned(),
            allow_any_host: s.allow_any_host,
            allowed_hosts: strs(&s.allowed_hosts),
            namespaces: s.namespaces.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::NvmetSubsysSpec> for NvmetSubsysSpec {
    type Error = ConvertError;
    fn try_from(s: pb::NvmetSubsysSpec) -> Result<Self, ConvertError> {
        Ok(NvmetSubsysSpec {
            nqn: Nqn::new(s.nqn)?,
            allow_any_host: s.allow_any_host,
            allowed_hosts: map_new(s.allowed_hosts, Nqn::new)?,
            namespaces: map_try(s.namespaces)?,
        })
    }
}

impl From<NvmetNsSpec> for pb::NvmetNsSpec {
    fn from(n: NvmetNsSpec) -> Self {
        pb::NvmetNsSpec {
            nsid: n.nsid,
            device_path: n.device_path.as_str().to_owned(),
        }
    }
}
impl TryFrom<pb::NvmetNsSpec> for NvmetNsSpec {
    type Error = ConvertError;
    fn try_from(n: pb::NvmetNsSpec) -> Result<Self, ConvertError> {
        Ok(NvmetNsSpec {
            nsid: n.nsid,
            device_path: DevicePath::new(n.device_path)?,
        })
    }
}

impl From<NvmetPortSpec> for pb::NvmetPortSpec {
    fn from(p: NvmetPortSpec) -> Self {
        pb::NvmetPortSpec {
            id: u32::from(p.id),
            trtype: pb::Transport::from(p.trtype) as i32,
            traddr: p.traddr.to_string(),
            trsvcid: u32::from(p.trsvcid),
            subsystems: strs(&p.subsystems),
        }
    }
}
impl TryFrom<pb::NvmetPortSpec> for NvmetPortSpec {
    type Error = ConvertError;
    fn try_from(p: pb::NvmetPortSpec) -> Result<Self, ConvertError> {
        Ok(NvmetPortSpec {
            id: to_u16(p.id, "port id")?,
            trtype: dec_transport(p.trtype)?,
            traddr: parse_ip(&p.traddr)?,
            trsvcid: to_u16(p.trsvcid, "trsvcid")?,
            subsystems: map_new(p.subsystems, Nqn::new)?,
        })
    }
}

impl From<LioDesired> for pb::LioDesired {
    fn from(d: LioDesired) -> Self {
        pb::LioDesired {
            backstores: d.backstores.into_iter().map(Into::into).collect(),
            targets: d.targets.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::LioDesired> for LioDesired {
    type Error = ConvertError;
    fn try_from(d: pb::LioDesired) -> Result<Self, ConvertError> {
        Ok(LioDesired {
            backstores: map_try(d.backstores)?,
            targets: map_try(d.targets)?,
        })
    }
}

impl From<LioBackstoreSpec> for pb::LioBackstoreSpec {
    fn from(b: LioBackstoreSpec) -> Self {
        pb::LioBackstoreSpec {
            name: b.name.as_str().to_owned(),
            device_path: b.device_path.as_str().to_owned(),
        }
    }
}
impl TryFrom<pb::LioBackstoreSpec> for LioBackstoreSpec {
    type Error = ConvertError;
    fn try_from(b: pb::LioBackstoreSpec) -> Result<Self, ConvertError> {
        Ok(LioBackstoreSpec {
            name: BackstoreName::new(b.name)?,
            device_path: DevicePath::new(b.device_path)?,
        })
    }
}

impl From<LioTargetSpec> for pb::LioTargetSpec {
    fn from(t: LioTargetSpec) -> Self {
        pb::LioTargetSpec {
            iqn: t.iqn.as_str().to_owned(),
            enabled: t.enabled,
            demo_mode: t.demo_mode,
            luns: t.luns.into_iter().map(Into::into).collect(),
            portals: t.portals.into_iter().map(Into::into).collect(),
            acls: strs(&t.acls),
        }
    }
}
impl TryFrom<pb::LioTargetSpec> for LioTargetSpec {
    type Error = ConvertError;
    fn try_from(t: pb::LioTargetSpec) -> Result<Self, ConvertError> {
        Ok(LioTargetSpec {
            iqn: Iqn::new(t.iqn)?,
            enabled: t.enabled,
            demo_mode: t.demo_mode,
            luns: map_try(t.luns)?,
            portals: map_try(t.portals)?,
            acls: map_new(t.acls, Iqn::new)?,
        })
    }
}

impl From<LioLunSpec> for pb::LioLunSpec {
    fn from(l: LioLunSpec) -> Self {
        pb::LioLunSpec {
            lun: l.lun,
            backstore: l.backstore.as_str().to_owned(),
        }
    }
}
impl TryFrom<pb::LioLunSpec> for LioLunSpec {
    type Error = ConvertError;
    fn try_from(l: pb::LioLunSpec) -> Result<Self, ConvertError> {
        Ok(LioLunSpec {
            lun: l.lun,
            backstore: BackstoreName::new(l.backstore)?,
        })
    }
}

impl From<LioPortalSpec> for pb::LioPortalSpec {
    fn from(p: LioPortalSpec) -> Self {
        pb::LioPortalSpec {
            addr: p.addr.to_string(),
            port: u32::from(p.port),
            iser: p.iser,
        }
    }
}
impl TryFrom<pb::LioPortalSpec> for LioPortalSpec {
    type Error = ConvertError;
    fn try_from(p: pb::LioPortalSpec) -> Result<Self, ConvertError> {
        Ok(LioPortalSpec {
            addr: parse_ip(&p.addr)?,
            port: to_u16(p.port, "portal port")?,
            iser: p.iser,
        })
    }
}

impl From<NfsDesired> for pb::NfsDesired {
    fn from(d: NfsDesired) -> Self {
        pb::NfsDesired {
            exports: d.exports.into_iter().map(Into::into).collect(),
            rdma_port: u32::from(d.rdma_port),
        }
    }
}
impl TryFrom<pb::NfsDesired> for NfsDesired {
    type Error = ConvertError;
    fn try_from(d: pb::NfsDesired) -> Result<Self, ConvertError> {
        Ok(NfsDesired {
            exports: map_try(d.exports)?,
            rdma_port: to_u16(d.rdma_port, "rdma_port")?,
        })
    }
}

impl From<NfsExportSpec> for pb::NfsExportSpec {
    fn from(e: NfsExportSpec) -> Self {
        pb::NfsExportSpec {
            path: e.path.as_str().to_owned(),
            fsid: e.fsid,
            clients: e.clients.into_iter().map(Into::into).collect(),
        }
    }
}
impl TryFrom<pb::NfsExportSpec> for NfsExportSpec {
    type Error = ConvertError;
    fn try_from(e: pb::NfsExportSpec) -> Result<Self, ConvertError> {
        Ok(NfsExportSpec {
            path: NfsExportPath::new(e.path)?,
            fsid: e.fsid,
            clients: map_try(e.clients)?,
        })
    }
}

impl From<NfsClientSpec> for pb::NfsClientSpec {
    fn from(c: NfsClientSpec) -> Self {
        pb::NfsClientSpec {
            client: c.client.as_str().to_owned(),
            rw: c.rw,
        }
    }
}
impl TryFrom<pb::NfsClientSpec> for NfsClientSpec {
    type Error = ConvertError;
    fn try_from(c: pb::NfsClientSpec) -> Result<Self, ConvertError> {
        Ok(NfsClientSpec {
            client: NfsClient::new(c.client)?,
            rw: c.rw,
        })
    }
}

// ---- AuthReply ----

impl From<AuthResult> for pb::AuthReply {
    fn from(r: AuthResult) -> Self {
        use pb::auth_reply::Result as R;
        let result = match r {
            AuthResult::Ok { username } => R::Ok(pb::OkAuth { username }),
            AuthResult::Err { kind, message } => R::Err(pb::ErrResponse {
                kind: pb::ErrKind::from(kind) as i32,
                message,
            }),
        };
        pb::AuthReply {
            result: Some(result),
        }
    }
}

impl TryFrom<pb::AuthReply> for AuthResult {
    type Error = ConvertError;
    fn try_from(r: pb::AuthReply) -> Result<Self, ConvertError> {
        use pb::auth_reply::Result as R;
        let result = r
            .result
            .ok_or_else(|| ConvertError("auth reply has no result set".into()))?;
        Ok(match result {
            R::Ok(a) => AuthResult::Ok {
                username: a.username,
            },
            R::Err(e) => {
                let kind = pb::ErrKind::try_from(e.kind)
                    .map_err(|_| ConvertError(format!("unknown error kind {}", e.kind)))?;
                AuthResult::Err {
                    kind: ErrKind::try_from(kind)?,
                    message: e.message,
                }
            }
        })
    }
}

// ---- Typed read replies (`actual::*` DTO <-> pb). Egress is the daemon
// serializing what it read; ingress is the web's lossy-graceful decode. ----

impl From<actual::nfs::ActualNfs> for pb::NfsReportReply {
    fn from(n: actual::nfs::ActualNfs) -> Self {
        pb::NfsReportReply {
            exports: n
                .exports
                .into_iter()
                .map(|e| pb::NfsExportEntryMsg {
                    path: e.path,
                    clients: e.clients,
                })
                .collect(),
            rdma_port: n.rdma_port.map(u32::from),
            managed: n
                .managed
                .into_iter()
                .map(|(path, client, rw)| pb::NfsManagedSpec { path, client, rw })
                .collect(),
        }
    }
}
impl From<pb::NfsReportReply> for actual::nfs::ActualNfs {
    fn from(n: pb::NfsReportReply) -> Self {
        actual::nfs::ActualNfs {
            exports: n
                .exports
                .into_iter()
                .map(|e| actual::nfs::NfsExportEntry {
                    path: e.path,
                    clients: e.clients,
                })
                .collect(),
            rdma_port: n.rdma_port.and_then(|p| u16::try_from(p).ok()),
            managed: n
                .managed
                .into_iter()
                .map(|m| (m.path, m.client, m.rw))
                .collect::<BTreeSet<_>>(),
        }
    }
}

impl From<actual::nvmet::ActualNvmet> for pb::NvmetReportReply {
    fn from(a: actual::nvmet::ActualNvmet) -> Self {
        pb::NvmetReportReply {
            subsystems: a
                .subsystems
                .into_iter()
                .map(|s| pb::ActualNvmetSubsys {
                    nqn: s.nqn,
                    allow_any_host: s.allow_any_host,
                    allowed_hosts: s.allowed_hosts,
                    namespaces: s
                        .namespaces
                        .into_iter()
                        .map(|n| pb::ActualNvmetNs {
                            nsid: n.nsid,
                            device_path: n.device_path,
                            enabled: n.enabled,
                        })
                        .collect(),
                })
                .collect(),
            ports: a
                .ports
                .into_iter()
                .map(|p| pb::ActualNvmetPort {
                    id: u32::from(p.id),
                    trtype: p.trtype,
                    traddr: p.traddr,
                    trsvcid: p.trsvcid,
                    subsystems: p.subsystems,
                })
                .collect(),
        }
    }
}
impl From<pb::NvmetReportReply> for actual::nvmet::ActualNvmet {
    fn from(a: pb::NvmetReportReply) -> Self {
        actual::nvmet::ActualNvmet {
            subsystems: a
                .subsystems
                .into_iter()
                .map(|s| actual::nvmet::Subsys {
                    nqn: s.nqn,
                    allow_any_host: s.allow_any_host,
                    allowed_hosts: s.allowed_hosts,
                    namespaces: s
                        .namespaces
                        .into_iter()
                        .map(|n| actual::nvmet::Namespace {
                            nsid: n.nsid,
                            device_path: n.device_path,
                            enabled: n.enabled,
                        })
                        .collect(),
                })
                .collect(),
            ports: a
                .ports
                .into_iter()
                .filter_map(|p| {
                    Some(actual::nvmet::Port {
                        id: u16::try_from(p.id).ok()?,
                        trtype: p.trtype,
                        traddr: p.traddr,
                        trsvcid: p.trsvcid,
                        subsystems: p.subsystems,
                    })
                })
                .collect(),
        }
    }
}

impl From<actual::lio::ActualLio> for pb::LioReportReply {
    fn from(a: actual::lio::ActualLio) -> Self {
        pb::LioReportReply {
            backstores: a
                .backstores
                .into_iter()
                .map(|b| pb::ActualLioBackstore {
                    name: b.name,
                    udev_path: b.udev_path,
                    enabled: b.enabled,
                })
                .collect(),
            targets: a
                .targets
                .into_iter()
                .map(|t| pb::ActualLioTarget {
                    iqn: t.iqn,
                    enabled: t.enabled,
                    demo_mode: t.demo_mode,
                    luns: t.luns,
                    portals: t
                        .portals
                        .into_iter()
                        .map(|p| pb::ActualLioPortal {
                            addr_port: p.addr_port,
                            iser: p.iser,
                        })
                        .collect(),
                    acls: t.acls,
                })
                .collect(),
        }
    }
}
impl From<pb::LioReportReply> for actual::lio::ActualLio {
    fn from(a: pb::LioReportReply) -> Self {
        actual::lio::ActualLio {
            backstores: a
                .backstores
                .into_iter()
                .map(|b| actual::lio::Backstore {
                    name: b.name,
                    udev_path: b.udev_path,
                    enabled: b.enabled,
                })
                .collect(),
            targets: a
                .targets
                .into_iter()
                .map(|t| actual::lio::Target {
                    iqn: t.iqn,
                    enabled: t.enabled,
                    demo_mode: t.demo_mode,
                    luns: t.luns,
                    portals: t
                        .portals
                        .into_iter()
                        .map(|p| actual::lio::Portal {
                            addr_port: p.addr_port,
                            iser: p.iser,
                        })
                        .collect(),
                    acls: t.acls,
                })
                .collect(),
        }
    }
}

impl From<Vec<actual::lio::IscsiSession>> for pb::LioSessionsReply {
    fn from(v: Vec<actual::lio::IscsiSession>) -> Self {
        pb::LioSessionsReply {
            sessions: v
                .into_iter()
                .map(|s| pb::IscsiSessionMsg {
                    target_iqn: s.target_iqn,
                    initiator_iqn: s.initiator_iqn,
                    detail: s.detail,
                })
                .collect(),
        }
    }
}
impl From<pb::LioSessionsReply> for Vec<actual::lio::IscsiSession> {
    fn from(r: pb::LioSessionsReply) -> Self {
        r.sessions
            .into_iter()
            .map(|s| actual::lio::IscsiSession {
                target_iqn: s.target_iqn,
                initiator_iqn: s.initiator_iqn,
                detail: s.detail,
            })
            .collect()
    }
}

impl From<Vec<actual::rdma::RdmaDev>> for pb::RdmaDevicesReply {
    fn from(v: Vec<actual::rdma::RdmaDev>) -> Self {
        pb::RdmaDevicesReply {
            devices: v
                .into_iter()
                .map(|d| pb::RdmaDevMsg {
                    name: d.name,
                    netdev: d.netdev,
                    active: d.active,
                    addrs: addr_strs(&d.addrs),
                })
                .collect(),
        }
    }
}
impl From<pb::RdmaDevicesReply> for Vec<actual::rdma::RdmaDev> {
    fn from(r: pb::RdmaDevicesReply) -> Self {
        r.devices
            .into_iter()
            .map(|d| actual::rdma::RdmaDev {
                name: d.name,
                netdev: d.netdev,
                active: d.active,
                addrs: parse_addrs(&d.addrs),
            })
            .collect()
    }
}

impl From<HashMap<String, Vec<IpAddr>>> for pb::NicPciAddrsReply {
    fn from(m: HashMap<String, Vec<IpAddr>>) -> Self {
        pb::NicPciAddrsReply {
            entries: m
                .into_iter()
                .map(|(pci, addrs)| pb::PciAddrIps {
                    pci,
                    addrs: addr_strs(&addrs),
                })
                .collect(),
        }
    }
}
impl From<pb::NicPciAddrsReply> for HashMap<String, Vec<IpAddr>> {
    fn from(r: pb::NicPciAddrsReply) -> Self {
        r.entries
            .into_iter()
            .map(|e| (e.pci, parse_addrs(&e.addrs)))
            .collect()
    }
}

impl From<actual::nic::NicStatus> for pb::NicStatusMsg {
    fn from(n: actual::nic::NicStatus) -> Self {
        use actual::nic::NicRdmaKind as K;
        let (kind, vendor) = match n.kind {
            K::Active => (pb::NicRdmaKind::Active, None),
            K::Inactive => (pb::NicRdmaKind::Inactive, None),
            K::CapableDisabled { vendor } => (pb::NicRdmaKind::CapableDisabled, Some(vendor)),
            K::SoftRoceable => (pb::NicRdmaKind::SoftRoceable, None),
            K::Unsupported => (pb::NicRdmaKind::Unsupported, None),
        };
        pb::NicStatusMsg {
            netdev: n.netdev,
            rdma: n.rdma,
            pci: n.pci.map(|p| p.as_str().to_owned()),
            addrs: addr_strs(&n.addrs),
            kind: kind as i32,
            vendor,
        }
    }
}

impl From<Vec<actual::nic::NicStatus>> for pb::NicInterfacesReply {
    fn from(v: Vec<actual::nic::NicStatus>) -> Self {
        pb::NicInterfacesReply {
            nics: v.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<pb::NicInterfacesReply> for Vec<actual::nic::NicStatus> {
    fn from(r: pb::NicInterfacesReply) -> Self {
        use actual::nic::NicRdmaKind as K;
        r.nics
            .into_iter()
            .map(|n| {
                let kind = match pb::NicRdmaKind::try_from(n.kind) {
                    Ok(pb::NicRdmaKind::Active) => K::Active,
                    Ok(pb::NicRdmaKind::Inactive) => K::Inactive,
                    Ok(pb::NicRdmaKind::CapableDisabled) => K::CapableDisabled {
                        vendor: n.vendor.unwrap_or_default(),
                    },
                    Ok(pb::NicRdmaKind::SoftRoceable) => K::SoftRoceable,
                    // Unknown / unspecified degrades to "not a candidate".
                    _ => K::Unsupported,
                };
                actual::nic::NicStatus {
                    netdev: n.netdev,
                    rdma: n.rdma,
                    pci: n.pci.and_then(|p| PciAddress::new(p).ok()),
                    addrs: parse_addrs(&n.addrs),
                    kind,
                }
            })
            .collect()
    }
}

impl From<actual::nic::NicNetwork> for pb::NicNetworkMsg {
    fn from(n: actual::nic::NicNetwork) -> Self {
        pb::NicNetworkMsg {
            netdev: n.netdev,
            mac: n.mac,
            mtu: n.mtu,
            operstate: n.operstate,
            dhcp: n.dhcp,
            addrs: n
                .addrs
                .into_iter()
                .map(|a| pb::NicAddrMsg {
                    addr: a.addr,
                    prefix: a.prefix as u32,
                    dynamic: a.dynamic,
                })
                .collect(),
            gateway: n.gateway,
        }
    }
}

impl From<Vec<actual::nic::NicNetwork>> for pb::NicNetworkReply {
    fn from(v: Vec<actual::nic::NicNetwork>) -> Self {
        pb::NicNetworkReply {
            nics: v.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<pb::NicNetworkReply> for Vec<actual::nic::NicNetwork> {
    fn from(r: pb::NicNetworkReply) -> Self {
        r.nics
            .into_iter()
            .map(|n| actual::nic::NicNetwork {
                netdev: n.netdev,
                mac: n.mac,
                mtu: n.mtu,
                operstate: n.operstate,
                dhcp: n.dhcp,
                addrs: n
                    .addrs
                    .into_iter()
                    .map(|a| actual::nic::NicAddr {
                        addr: a.addr,
                        prefix: a.prefix as u8,
                        dynamic: a.dynamic,
                    })
                    .collect(),
                gateway: n.gateway,
            })
            .collect()
    }
}

impl From<HashMap<String, String>> for pb::RoceCapableNicsReply {
    fn from(m: HashMap<String, String>) -> Self {
        pb::RoceCapableNicsReply {
            nics: m
                .into_iter()
                .map(|(netdev, vendor)| pb::RoceCapableNic { netdev, vendor })
                .collect(),
        }
    }
}
impl From<pb::RoceCapableNicsReply> for HashMap<String, String> {
    fn from(r: pb::RoceCapableNicsReply) -> Self {
        r.nics.into_iter().map(|n| (n.netdev, n.vendor)).collect()
    }
}

impl From<HashMap<String, actual::nic::NicAdvice>> for pb::NicRdmaAdviceReply {
    fn from(m: HashMap<String, actual::nic::NicAdvice>) -> Self {
        pb::NicRdmaAdviceReply {
            advice: m
                .into_iter()
                .map(|(netdev, a)| pb::NicAdviceMsg {
                    netdev,
                    label: a.label,
                    detail: a.detail,
                })
                .collect(),
        }
    }
}
impl From<pb::NicRdmaAdviceReply> for HashMap<String, actual::nic::NicAdvice> {
    fn from(r: pb::NicRdmaAdviceReply) -> Self {
        r.advice
            .into_iter()
            .map(|a| {
                (
                    a.netdev,
                    actual::nic::NicAdvice {
                        label: a.label,
                        detail: a.detail,
                    },
                )
            })
            .collect()
    }
}

// ---- TaskEvent ----

impl From<SubStatus> for pb::SubStatus {
    fn from(s: SubStatus) -> Self {
        match s {
            SubStatus::Success => pb::SubStatus::Success,
            SubStatus::Failed => pb::SubStatus::Failed,
            SubStatus::Skipped => pb::SubStatus::Skipped,
        }
    }
}
impl TryFrom<i32> for SubStatus {
    type Error = ConvertError;
    fn try_from(i: i32) -> Result<Self, ConvertError> {
        let p = pb::SubStatus::try_from(i)
            .map_err(|_| ConvertError(format!("unknown sub status {i}")))?;
        Ok(match p {
            pb::SubStatus::Success => SubStatus::Success,
            pb::SubStatus::Failed => SubStatus::Failed,
            pb::SubStatus::Skipped => SubStatus::Skipped,
            pb::SubStatus::Unspecified => {
                return Err(ConvertError("unspecified sub status".into()));
            }
        })
    }
}

impl From<TaskEvent> for pb::TaskEvent {
    fn from(ev: TaskEvent) -> Self {
        use pb::task_event::Event;
        let event = match ev {
            TaskEvent::SubtaskStarted {
                name,
                command,
                args,
                stdin,
            } => Event::SubtaskStarted(pb::SubtaskStarted {
                name,
                command,
                args,
                stdin,
            }),
            TaskEvent::Stdout { data } => Event::Stdout(pb::Output { data }),
            TaskEvent::Stderr { data } => Event::Stderr(pb::Output { data }),
            TaskEvent::SubtaskFinished {
                status,
                exit,
                error,
            } => Event::SubtaskFinished(pb::SubtaskFinished {
                status: pb::SubStatus::from(status) as i32,
                exit,
                error,
            }),
            TaskEvent::Finished { status, error } => Event::Finished(pb::Finished {
                status: pb::SubStatus::from(status) as i32,
                error,
            }),
        };
        pb::TaskEvent { event: Some(event) }
    }
}

impl TryFrom<pb::TaskEvent> for TaskEvent {
    type Error = ConvertError;
    fn try_from(ev: pb::TaskEvent) -> Result<Self, ConvertError> {
        use pb::task_event::Event;
        let event = ev
            .event
            .ok_or_else(|| ConvertError("task event has no event set".into()))?;
        Ok(match event {
            Event::SubtaskStarted(s) => TaskEvent::SubtaskStarted {
                name: s.name,
                command: s.command,
                args: s.args,
                stdin: s.stdin,
            },
            Event::Stdout(o) => TaskEvent::Stdout { data: o.data },
            Event::Stderr(o) => TaskEvent::Stderr { data: o.data },
            Event::SubtaskFinished(f) => TaskEvent::SubtaskFinished {
                status: SubStatus::try_from(f.status)?,
                exit: f.exit,
                error: f.error,
            },
            Event::Finished(f) => TaskEvent::Finished {
                status: SubStatus::try_from(f.status)?,
                error: f.error,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn auth_reply_and_task_event_roundtrip() {
        for resp in [
            AuthResult::Ok {
                username: "alice".into(),
            },
            AuthResult::Err {
                kind: ErrKind::AuthFailed,
                message: "invalid username or password".into(),
            },
        ] {
            let decoded =
                pb::AuthReply::decode(pb::AuthReply::from(resp.clone()).encode_to_vec().as_slice())
                    .unwrap();
            assert_eq!(AuthResult::try_from(decoded).unwrap(), resp);
        }
        assert!(AuthResult::try_from(pb::AuthReply { result: None }).is_err());

        for ev in [
            TaskEvent::SubtaskStarted {
                name: "Create zvol".into(),
                command: Some("zfs".into()),
                args: vec!["create".into()],
                stdin: Some("x".into()),
            },
            TaskEvent::SubtaskStarted {
                name: "Load kernel modules".into(),
                command: None,
                args: vec![],
                stdin: None,
            },
            TaskEvent::Stdout { data: "out".into() },
            TaskEvent::Stderr { data: "err".into() },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Success,
                exit: 0,
                error: None,
            },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Failed,
                exit: 1,
                error: Some("boom".into()),
            },
            TaskEvent::SubtaskFinished {
                status: SubStatus::Skipped,
                exit: 0,
                error: None,
            },
            TaskEvent::Finished {
                status: SubStatus::Success,
                error: None,
            },
            TaskEvent::Finished {
                status: SubStatus::Failed,
                error: Some("boom".into()),
            },
        ] {
            let decoded =
                pb::TaskEvent::decode(pb::TaskEvent::from(ev.clone()).encode_to_vec().as_slice())
                    .unwrap();
            assert_eq!(TaskEvent::try_from(decoded).unwrap(), ev);
        }
        // A `SubStatus` of 0 (UNSPECIFIED) is rejected on ingress, mirroring the
        // other enum-ingress checks — an unset status must not decode as Success.
        for bad in [
            pb::task_event::Event::SubtaskFinished(pb::SubtaskFinished {
                status: 0,
                exit: 0,
                error: None,
            }),
            pb::task_event::Event::Finished(pb::Finished {
                status: 0,
                error: None,
            }),
        ] {
            assert!(TaskEvent::try_from(pb::TaskEvent { event: Some(bad) }).is_err());
        }
    }

    /// Each typed read reply must round-trip its DTO (daemon egress → wire →
    /// web ingress), with unparseable addresses dropping out rather than
    /// failing the whole reply.
    #[test]
    fn read_replies_roundtrip() {
        use crate::actual::{lio, nfs, nic, nvmet, rdma};

        let nvmet = nvmet::ActualNvmet {
            subsystems: vec![nvmet::Subsys {
                nqn: "nqn.2026-06.io.greendot:vm1".into(),
                allow_any_host: false,
                allowed_hosts: vec!["nqn.2014-08.org.nvmexpress:host1".into()],
                namespaces: vec![nvmet::Namespace {
                    nsid: 1,
                    device_path: "/dev/zvol/tank/vm1".into(),
                    enabled: true,
                }],
            }],
            ports: vec![nvmet::Port {
                id: 1,
                trtype: "rdma".into(),
                traddr: "10.0.0.5".into(),
                trsvcid: "4420".into(),
                subsystems: vec!["nqn.2026-06.io.greendot:vm1".into()],
            }],
        };
        assert_eq!(
            nvmet::ActualNvmet::from(pb::NvmetReportReply::from(nvmet.clone())),
            nvmet
        );

        let lio = lio::ActualLio {
            backstores: vec![lio::Backstore {
                name: "vm1".into(),
                udev_path: "/dev/zvol/tank/vm1".into(),
                enabled: true,
            }],
            targets: vec![lio::Target {
                iqn: "iqn.2026-06.io.greendot:vm1".into(),
                enabled: true,
                demo_mode: false,
                luns: vec!["vm1".into()],
                portals: vec![lio::Portal {
                    addr_port: "[::1]:3260".into(),
                    iser: true,
                }],
                acls: vec!["iqn.1993-08.org.debian:01:abc".into()],
            }],
        };
        assert_eq!(
            lio::ActualLio::from(pb::LioReportReply::from(lio.clone())),
            lio
        );

        let sessions = vec![lio::IscsiSession {
            target_iqn: "iqn.2026-06.io.greendot:vm1".into(),
            initiator_iqn: "iqn.1993-08.org.debian:01:abc".into(),
            detail: "LOGGED_IN".into(),
        }];
        assert_eq!(
            Vec::<lio::IscsiSession>::from(pb::LioSessionsReply::from(sessions.clone())),
            sessions
        );

        let devs = vec![rdma::RdmaDev {
            name: "rxe0".into(),
            netdev: Some("eth0".into()),
            active: true,
            addrs: vec!["10.0.0.5".parse().unwrap()],
        }];
        assert_eq!(
            Vec::<rdma::RdmaDev>::from(pb::RdmaDevicesReply::from(devs.clone())),
            devs
        );
        // A bad address drops out on ingress instead of failing the reply.
        let mut wire = pb::RdmaDevicesReply::from(devs.clone());
        wire.devices[0].addrs.push("not-an-ip".into());
        assert_eq!(Vec::<rdma::RdmaDev>::from(wire), devs);

        let nics = vec![
            nic::NicStatus {
                netdev: "eth0".into(),
                rdma: Some("rxe0".into()),
                pci: Some(crate::PciAddress::new("0000:00:10.0").unwrap()),
                addrs: vec!["10.0.0.5".parse().unwrap()],
                kind: nic::NicRdmaKind::Active,
            },
            nic::NicStatus {
                netdev: "ens16".into(),
                rdma: None,
                pci: None,
                addrs: vec![],
                kind: nic::NicRdmaKind::CapableDisabled {
                    vendor: "Acme".into(),
                },
            },
        ];
        assert_eq!(
            Vec::<nic::NicStatus>::from(pb::NicInterfacesReply::from(nics.clone())),
            nics
        );

        let nfs = nfs::ActualNfs {
            exports: vec![nfs::NfsExportEntry {
                path: "/tank/share".into(),
                clients: vec!["192.168.101.0/24".into()],
            }],
            rdma_port: Some(20049),
            managed: [(
                "/tank/share".to_owned(),
                "192.168.101.0/24".to_owned(),
                true,
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            nfs::ActualNfs::from(pb::NfsReportReply::from(nfs.clone())),
            nfs
        );

        let capable: HashMap<String, String> = [("ens16".to_owned(), "Acme".to_owned())].into();
        assert_eq!(
            HashMap::<String, String>::from(pb::RoceCapableNicsReply::from(capable.clone())),
            capable
        );

        let advice: HashMap<String, nic::NicAdvice> = [(
            "ens16v0".to_owned(),
            nic::NicAdvice {
                label: "Load the driver".into(),
                detail: "do X first".into(),
            },
        )]
        .into();
        assert_eq!(
            HashMap::<String, nic::NicAdvice>::from(pb::NicRdmaAdviceReply::from(advice.clone())),
            advice
        );

        let pci: HashMap<String, Vec<IpAddr>> =
            [("0000:00:10.0".to_owned(), vec!["10.0.0.5".parse().unwrap()])].into();
        assert_eq!(
            HashMap::<String, Vec<IpAddr>>::from(pb::NicPciAddrsReply::from(pci.clone())),
            pci
        );
    }
}
