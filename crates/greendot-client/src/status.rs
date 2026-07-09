//! Read-only actual state on the initiator: fabric NVMe controllers from
//! /sys/class/nvme, NFS mounts from /proc/mounts, RDMA readiness from
//! /sys/class/infiniband and /sys/module. All parsers take injected roots so
//! tests run over tempdir fixtures; nothing here needs privilege.

use std::path::{Path, PathBuf};

/// One fabric controller under /sys/class/nvme (PCIe controllers, which have
/// no `subsysnqn`-reachable fabric identity we care about, still parse — the
/// callers match by NQN so they never see them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvmeController {
    /// Controller name, e.g. `nvme0`.
    pub name: String,
    pub subsysnqn: String,
    /// `rdma` / `tcp` / `loop` / `pcie`.
    pub transport: String,
    /// `live` / `connecting` / `deleting` / ...
    pub state: String,
    /// e.g. `traddr=10.0.0.5,trsvcid=4420`.
    pub address: String,
    pub hostnqn: Option<String>,
    /// Block devices of this controller's namespaces, e.g. `/dev/nvme0n1`.
    /// Multipath layouts (`nvme0c0n1`) fold onto the subsystem device name.
    pub namespaces: Vec<String>,
}

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

/// `nvme0c0n1` → `nvme0n1`; `nvme0n1` stays. Anything else → None.
fn namespace_blockdev(entry: &str) -> Option<String> {
    let rest = entry.strip_prefix("nvme")?;
    let (ctrl, rest) = split_digits(rest)?;
    let rest = match rest.strip_prefix('c') {
        // Multipath path device: the block device belongs to the subsystem,
        // keyed by the *controller* number here — nvme<C>c<X>n<N> maps to the
        // subsystem's nvme<S>n<N> which we can't derive locally, so use the
        // path name's own numbers (the /dev node exists either way on
        // non-multipath; on multipath the subsystem device also enumerates).
        Some(rest) => split_digits(rest)?.1,
        None => rest,
    };
    let (ns, rest) = split_digits(rest.strip_prefix('n')?)?;
    rest.is_empty().then(|| format!("nvme{ctrl}n{ns}"))
}

fn split_digits(s: &str) -> Option<(&str, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    (end > 0).then(|| s.split_at(end))
}

/// Parses every controller under `sys_class_nvme` (i.e. /sys/class/nvme).
pub fn nvme_controllers(sys_class_nvme: &Path) -> Vec<NvmeController> {
    let Ok(entries) = std::fs::read_dir(sys_class_nvme) else {
        return vec![];
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(subsysnqn) = read_trim(&dir.join("subsysnqn")) else {
            continue;
        };
        let mut namespaces: Vec<String> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| namespace_blockdev(&e.file_name().to_string_lossy()))
            .map(|dev| format!("/dev/{dev}"))
            .collect();
        namespaces.sort();
        namespaces.dedup();
        out.push(NvmeController {
            name,
            subsysnqn,
            transport: read_trim(&dir.join("transport")).unwrap_or_default(),
            state: read_trim(&dir.join("state")).unwrap_or_default(),
            address: read_trim(&dir.join("address")).unwrap_or_default(),
            hostnqn: read_trim(&dir.join("hostnqn")).filter(|s| !s.is_empty()),
            namespaces,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// One NFS mount from /proc/mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsMount {
    /// The mount source, e.g. `10.0.0.5:/tank/share`.
    pub source: String,
    pub mountpoint: String,
    /// The kernel normalizes an `-o rdma` mount to `proto=rdma` here.
    pub rdma: bool,
}

/// Decodes /proc/mounts octal escapes (`\040` = space).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let digits: String = chars.clone().take(3).collect();
        match u8::from_str_radix(&digits, 8) {
            Ok(b) if digits.len() == 3 => {
                out.push(b as char);
                chars.nth(2);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parses the NFS mounts out of `proc_mounts` (i.e. /proc/mounts).
pub fn nfs_mounts(proc_mounts: &Path) -> Vec<NfsMount> {
    let Ok(text) = std::fs::read_to_string(proc_mounts) else {
        return vec![];
    };
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let (source, mountpoint, fstype, opts) = (f.next()?, f.next()?, f.next()?, f.next()?);
            if fstype != "nfs" && fstype != "nfs4" {
                return None;
            }
            Some(NfsMount {
                source: unescape(source),
                mountpoint: unescape(mountpoint),
                rdma: opts.split(',').any(|o| o == "proto=rdma" || o == "rdma"),
            })
        })
        .collect()
}

/// RDMA devices with at least one ACTIVE port (i.e. usable for a connect).
pub fn active_rdma_devices(sys_class_infiniband: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(sys_class_infiniband) else {
        return vec![];
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|dev| {
            std::fs::read_dir(dev.path().join("ports"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|port| {
                    read_trim(&port.path().join("state"))
                        .is_some_and(|s| s.to_ascii_uppercase().contains("ACTIVE"))
                })
        })
        .map(|dev| dev.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// Whether a kernel module is loaded (or built in): /sys/module/<name>.
pub fn module_loaded(sys_module: &Path, name: &str) -> bool {
    sys_module.join(name).is_dir()
}

/// Roots for every read this module does — injected so tests (and the agent's
/// `--sys-root`) can point at fixtures.
#[derive(Debug, Clone)]
pub struct SysRoots {
    pub sys_class_nvme: PathBuf,
    pub sys_class_infiniband: PathBuf,
    pub sys_module: PathBuf,
    pub proc_mounts: PathBuf,
}

impl SysRoots {
    pub fn at(root: &Path) -> SysRoots {
        SysRoots {
            sys_class_nvme: root.join("sys/class/nvme"),
            sys_class_infiniband: root.join("sys/class/infiniband"),
            sys_module: root.join("sys/module"),
            proc_mounts: root.join("proc/mounts"),
        }
    }
}

impl Default for SysRoots {
    fn default() -> Self {
        SysRoots::at(Path::new("/"))
    }
}

// ---- the client-side dot ----

/// Mirrors the target's green/yellow/red semantics from the initiator's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dot {
    Green,
    Yellow,
    Red,
}

impl Dot {
    pub fn as_str(self) -> &'static str {
        match self {
            Dot::Green => "green",
            Dot::Yellow => "yellow",
            Dot::Red => "red",
        }
    }
}

/// The dot for an NVMe export: green = a live RDMA controller, yellow = live
/// over another transport, red = absent or not live.
pub fn nvme_dot<'c>(
    nqn: &str,
    controllers: &'c [NvmeController],
) -> (Dot, String, Option<&'c NvmeController>) {
    let Some(c) = controllers.iter().find(|c| c.subsysnqn == nqn) else {
        return (Dot::Red, "not connected".into(), None);
    };
    match (c.state.as_str(), c.transport.as_str()) {
        ("live", "rdma") => (Dot::Green, "connected over RDMA".into(), Some(c)),
        ("live", t) => (
            Dot::Yellow,
            format!("connected over {t}, not RDMA"),
            Some(c),
        ),
        (s, _) => (Dot::Red, format!("controller {s}"), Some(c)),
    }
}

/// The dot for an NFS export: matched by exact `host:path` source first, then
/// by `:path` suffix (manual mounts of the same export).
pub fn nfs_dot<'m>(
    host: &str,
    path: &str,
    mounts: &'m [NfsMount],
) -> (Dot, String, Option<&'m NfsMount>) {
    let exact = format!("{host}:{path}");
    let suffix = format!(":{path}");
    let m = mounts
        .iter()
        .find(|m| m.source == exact)
        .or_else(|| mounts.iter().find(|m| m.source.ends_with(&suffix)));
    match m {
        None => (Dot::Red, "not mounted".into(), None),
        Some(m) if m.rdma => (Dot::Green, "mounted over RDMA".into(), Some(m)),
        Some(m) => (Dot::Yellow, "mounted over TCP, not RDMA".into(), Some(m)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::path::PathBuf;

    /// Builds a /sys-shaped fixture tree and returns its root.
    fn fixture() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("gd-status-{}-{}", std::process::id(), rand_tag()));
        let nvme = root.join("sys/class/nvme");
        // nvme0: live fabric controller over rdma with one namespace.
        let d = nvme.join("nvme0");
        std::fs::create_dir_all(d.join("nvme0n1")).unwrap();
        for (f, v) in [
            ("subsysnqn", "nqn.2026-06.io.greendot:vm1"),
            ("transport", "rdma"),
            ("state", "live"),
            ("address", "traddr=10.0.0.5,trsvcid=4420"),
            ("hostnqn", "nqn.2014-08.org.nvmexpress:uuid:h1"),
        ] {
            std::fs::write(d.join(f), format!("{v}\n")).unwrap();
        }
        // nvme1: tcp, still connecting, multipath-style namespace dir.
        let d = nvme.join("nvme1");
        std::fs::create_dir_all(d.join("nvme1c1n2")).unwrap();
        for (f, v) in [
            ("subsysnqn", "nqn.2026-06.io.greendot:vm2"),
            ("transport", "tcp"),
            ("state", "connecting"),
            ("address", "traddr=10.0.0.5,trsvcid=4420"),
        ] {
            std::fs::write(d.join(f), format!("{v}\n")).unwrap();
        }
        // A PCIe controller with no fabric files — must not blow up parsing.
        std::fs::create_dir_all(nvme.join("nvme2")).unwrap();

        // RDMA device with an ACTIVE port + one DOWN device.
        for (dev, state) in [("rxe0", "4: ACTIVE"), ("mlx5_1", "1: DOWN")] {
            let p = root.join("sys/class/infiniband").join(dev).join("ports/1");
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("state"), state).unwrap();
        }
        std::fs::create_dir_all(root.join("sys/module/nvme_rdma")).unwrap();

        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::write(
            root.join("proc/mounts"),
            "sysfs /sys sysfs rw 0 0\n\
             10.0.0.5:/tank/share /mnt/greendot/nas1/share nfs4 rw,proto=rdma,port=20049 0 0\n\
             10.0.0.6:/srv/x /mnt/x\\040y nfs rw,proto=tcp 0 0\n",
        )
        .unwrap();
        root
    }

    fn rand_tag() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    }

    #[test]
    fn parses_controllers_mounts_rdma_and_modules() {
        let root = fixture();
        let roots = SysRoots::at(&root);

        // The subsysnqn-less dir (old PCIe layout) is skipped, not an error.
        let ctrls = nvme_controllers(&roots.sys_class_nvme);
        assert_eq!(ctrls.len(), 2, "{ctrls:?}");
        let vm1 = &ctrls[0];
        assert_eq!(
            (
                vm1.name.as_str(),
                vm1.subsysnqn.as_str(),
                vm1.transport.as_str(),
                vm1.state.as_str()
            ),
            ("nvme0", "nqn.2026-06.io.greendot:vm1", "rdma", "live")
        );
        assert_eq!(vm1.namespaces, ["/dev/nvme0n1"]);
        assert_eq!(
            vm1.hostnqn.as_deref(),
            Some("nqn.2014-08.org.nvmexpress:uuid:h1")
        );
        // Multipath dir name folds to the plain blockdev name.
        assert_eq!(ctrls[1].namespaces, ["/dev/nvme1n2"]);

        let mounts = nfs_mounts(&roots.proc_mounts);
        assert_eq!(mounts.len(), 2);
        assert_eq!(
            (mounts[0].source.as_str(), mounts[0].rdma),
            ("10.0.0.5:/tank/share", true)
        );
        // Octal-escaped mountpoint decoded.
        assert_eq!(mounts[1].mountpoint, "/mnt/x y");
        assert!(!mounts[1].rdma);

        assert_eq!(active_rdma_devices(&roots.sys_class_infiniband), ["rxe0"]);
        assert!(module_loaded(&roots.sys_module, "nvme_rdma"));
        assert!(!module_loaded(&roots.sys_module, "rpcrdma"));

        std::fs::remove_dir_all(&root).ok();
    }

    #[rstest]
    #[case("nvme0n1", Some("nvme0n1"))]
    #[case("nvme12n3", Some("nvme12n3"))]
    #[case("nvme0c2n1", Some("nvme0n1"))]
    #[case("nvme0", None)]
    #[case("nvme0n1p2", None)]
    #[case("ng0n1", None)]
    fn namespace_names(#[case] entry: &str, #[case] expect: Option<&str>) {
        assert_eq!(super::namespace_blockdev(entry).as_deref(), expect);
    }

    #[test]
    fn dots_from_fixture() {
        let root = fixture();
        let roots = SysRoots::at(&root);
        let ctrls = nvme_controllers(&roots.sys_class_nvme);
        let mounts = nfs_mounts(&roots.proc_mounts);

        // live+rdma → green; connecting → red with the state as reason;
        // unknown nqn → red not-connected.
        let (dot, _, c) = nvme_dot("nqn.2026-06.io.greendot:vm1", &ctrls);
        assert_eq!(dot, Dot::Green);
        assert_eq!(c.unwrap().namespaces, ["/dev/nvme0n1"]);
        let (dot, reason, _) = nvme_dot("nqn.2026-06.io.greendot:vm2", &ctrls);
        assert_eq!((dot, reason.as_str()), (Dot::Red, "controller connecting"));
        let (dot, ..) = nvme_dot("nqn.2026-06.io.greendot:gone", &ctrls);
        assert_eq!(dot, Dot::Red);

        // Exact host:path match green over rdma; tcp mount yellow; missing red.
        let (dot, _, m) = nfs_dot("10.0.0.5", "/tank/share", &mounts);
        assert_eq!(dot, Dot::Green);
        assert_eq!(m.unwrap().mountpoint, "/mnt/greendot/nas1/share");
        let (dot, ..) = nfs_dot("10.0.0.6", "/srv/x", &mounts);
        assert_eq!(dot, Dot::Yellow);
        // Suffix match: same path served from a host alias still matches.
        let (dot, ..) = nfs_dot("nas1.local", "/tank/share", &mounts);
        assert_eq!(dot, Dot::Green);
        let (dot, ..) = nfs_dot("10.0.0.5", "/nope", &mounts);
        assert_eq!(dot, Dot::Red);

        std::fs::remove_dir_all(&root).ok();
    }
}
