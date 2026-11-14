//! The privileged primitives — everything the root agent (or a sudo'd CLI)
//! actually does: write /dev/nvme-fabrics, delete controllers via sysfs,
//! exec mount/umount, and mint /etc/nvme/hostnqn. No network access here;
//! every string that reaches a kernel interface or an argv is a validated
//! newtype or an explicitly checked path (mount/umount are exec'd argv,
//! never a shell).

use crate::status;
use anyhow::{Context, Result, bail};
use greendot_proto::{Nqn, Transport};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Paths the privileged ops touch — injected for tests and the agent's
/// `--sys-root`.
#[derive(Debug, Clone)]
pub struct PrivPaths {
    pub fabrics: PathBuf,
    pub etc_nvme: PathBuf,
    pub sys: status::SysRoots,
}

impl PrivPaths {
    pub fn at(root: &Path) -> PrivPaths {
        PrivPaths {
            fabrics: root.join("dev/nvme-fabrics"),
            etc_nvme: root.join("etc/nvme"),
            sys: status::SysRoots::at(root),
        }
    }
}

impl Default for PrivPaths {
    fn default() -> Self {
        PrivPaths::at(Path::new("/"))
    }
}

/// Reads /etc/nvme/hostnqn, generating and persisting one (0644, like
/// nvme-cli's) on first use.
pub fn ensure_hostnqn(etc_nvme: &Path) -> Result<String> {
    let path = etc_nvme.join("hostnqn");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim();
        if !existing.is_empty() {
            return Ok(existing.to_owned());
        }
    }
    let hostnqn = format!("nqn.2014-08.org.nvmexpress:uuid:{}", random_uuid()?);
    std::fs::create_dir_all(etc_nvme)
        .with_context(|| format!("creating {}", etc_nvme.display()))?;
    std::fs::write(&path, format!("{hostnqn}\n"))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(hostnqn)
}

/// Reads /etc/nvme/hostid, persisting one on first use: the uuid inside a
/// `…:uuid:<uuid>` hostnqn (as nvme-cli derives it), else a fresh one. A
/// hostnqn passed without its hostid gets the kernel's default hostid, which
/// is already bound to the kernel's default NQN — the connect then fails with
/// EINVAL ("same hostid but different hostnqn").
pub fn ensure_hostid(etc_nvme: &Path, hostnqn: &Nqn) -> Result<String> {
    // It lands in the comma-separated fabrics string: a uuid or nothing.
    let is_uuid = |s: &str| s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    let path = etc_nvme.join("hostid");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim();
        if !existing.is_empty() {
            if !is_uuid(existing) {
                bail!("{} does not hold a uuid: {existing:?}", path.display());
            }
            return Ok(existing.to_owned());
        }
    }
    let hostid = match hostnqn.as_str().split_once(":uuid:") {
        Some((_, uuid)) if is_uuid(uuid) => uuid.to_owned(),
        _ => random_uuid()?,
    };
    std::fs::create_dir_all(etc_nvme)
        .with_context(|| format!("creating {}", etc_nvme.display()))?;
    std::fs::write(&path, format!("{hostid}\n"))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(hostid)
}

fn random_uuid() -> Result<String> {
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("reading /proc/sys/kernel/random/uuid")?;
    Ok(uuid.trim().to_owned())
}

/// Connects one NVMe-oF controller and waits for it to come live with a
/// namespace block device, rolling the controller back on timeout. Returns
/// the device path. An EALREADY write means an existing connection — reused.
pub fn connect_nvme(
    paths: &PrivPaths,
    nqn: &Nqn,
    transport: Transport,
    traddr: IpAddr,
    trsvcid: u16,
    hostnqn: &Nqn,
) -> Result<String> {
    if transport == Transport::Loop {
        bail!("loop transport is target-local only");
    }
    let hostid = ensure_hostid(&paths.etc_nvme, hostnqn)?;
    // Every field is a validated newtype, a typed value, or a checked uuid — no
    // field can carry a comma, so the option string cannot be smuggled into.
    let options = format!(
        "nqn={nqn},transport={},traddr={traddr},trsvcid={trsvcid},hostnqn={hostnqn},hostid={hostid}",
        transport.as_str()
    );
    let write = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&paths.fabrics)
        .and_then(|mut f| f.write_all(options.as_bytes()));
    match write {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "{} does not exist — load the fabrics module first (modprobe nvme-{})",
            paths.fabrics.display(),
            transport.as_str()
        ),
        // EALREADY: the kernel already holds this association — reuse it.
        Err(e) if e.raw_os_error() == Some(nix::libc::EALREADY) => {}
        Err(e) => {
            return Err(e)
                .with_context(|| format!("connect write to {} failed", paths.fabrics.display()));
        }
    }

    // The controller appears in /sys/class/nvme quickly; live + namespace can
    // take a few seconds (ACL rejection shows up as it never leaving
    // `connecting`, then getting deleted).
    for _ in 0..20 {
        let ctrls = status::nvme_controllers(&paths.sys.sys_class_nvme);
        if let Some(c) = ctrls.iter().find(|c| c.subsysnqn == nqn.as_str()) {
            if c.state == "live"
                && let Some(dev) = c.namespaces.first()
            {
                return Ok(dev.clone());
            }
            if c.state == "dead" || c.state == "deleting" {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let deleted = disconnect_nvme(&paths.sys.sys_class_nvme, nqn).unwrap_or(0);
    bail!(
        "controller for {nqn} did not come live within 10s{} — is this host's NQN \
         in the export's allowed initiators, and {traddr} reachable?",
        if deleted > 0 { " (rolled back)" } else { "" }
    )
}

/// Deletes every controller bound to `nqn` (writing 1 to `delete_controller`,
/// like `nvme disconnect -n`). Returns how many were deleted.
pub fn disconnect_nvme(sys_class_nvme: &Path, nqn: &Nqn) -> Result<u32> {
    let mut deleted = 0;
    for c in status::nvme_controllers(sys_class_nvme) {
        if c.subsysnqn != nqn.as_str() {
            continue;
        }
        let path = sys_class_nvme.join(&c.name).join("delete_controller");
        std::fs::write(&path, "1").with_context(|| format!("writing {}", path.display()))?;
        deleted += 1;
    }
    Ok(deleted)
}

/// A path fit to appear in a mount argv: absolute, no `..`, no whitespace or
/// characters that could split/quote (the exec never goes through a shell —
/// this is defense in depth and keeps /proc/mounts parseable).
pub fn safe_mount_path(s: &str) -> Result<()> {
    let ok = s.starts_with('/')
        && !s.contains("..")
        && !s.contains(',')
        && !s.chars().any(|c| c.is_whitespace() || c.is_control());
    if !ok {
        bail!("unsafe path {s:?}");
    }
    Ok(())
}

/// A host fit for the `host:path` mount source (a leading `-` would read as
/// a mount option).
pub fn safe_mount_host(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c));
    if !ok {
        bail!("unsafe host {s:?}");
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd} (is it installed?)"))?;
    if !out.status.success() {
        bail!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Where a non-root caller may mount: the CLI's default mountpoints.
pub const MANAGED_MOUNT_ROOT: &str = "/mnt/greendot";

/// Confines a non-root caller (an agent peer in the group) to
/// `/mnt/greendot/<target>/<export>`, reached without a symlink. Anywhere else,
/// a mounted server's files — or an unmount — would land as root wherever the
/// caller chose (e.g. over /etc/sudoers.d).
fn confine_mountpoint(mountpoint: &str, create: bool) -> Result<()> {
    let plain = |p: &str| !p.is_empty() && p != "." && !p.contains('/');
    let Some((target, export)) = mountpoint
        .strip_prefix(MANAGED_MOUNT_ROOT)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split_once('/'))
        .filter(|(target, export)| plain(target) && plain(export))
    else {
        bail!(
            "only root may use a mountpoint outside {MANAGED_MOUNT_ROOT}/<target>/<export>: {mountpoint:?}"
        );
    };
    if create {
        std::fs::create_dir_all(mountpoint).with_context(|| format!("creating {mountpoint}"))?;
    }
    let real =
        std::fs::canonicalize(mountpoint).with_context(|| format!("resolving {mountpoint}"))?;
    let expected = std::fs::canonicalize(MANAGED_MOUNT_ROOT)
        .with_context(|| format!("resolving {MANAGED_MOUNT_ROOT}"))?
        .join(target)
        .join(export);
    if real != expected {
        bail!(
            "{mountpoint} resolves through a symlink to {}",
            real.display()
        );
    }
    Ok(())
}

/// Mounts `host:path` at `mountpoint` (created if missing) over NFS —
/// `proto=rdma,port=<port>` or plain TCP. Uses /usr/bin/mount so mount.nfs
/// handles version/addr negotiation. `confined` callers are held to
/// [`MANAGED_MOUNT_ROOT`].
pub fn mount_nfs(
    host: &str,
    path: &str,
    mountpoint: &str,
    rdma: bool,
    port: u16,
    confined: bool,
) -> Result<()> {
    safe_mount_host(host)?;
    safe_mount_path(path)?;
    safe_mount_path(mountpoint)?;
    if confined {
        confine_mountpoint(mountpoint, true)?;
    } else {
        std::fs::create_dir_all(mountpoint).with_context(|| format!("creating {mountpoint}"))?;
    }
    // The server's setuid binaries and device nodes are not ours to trust.
    let opts = if rdma {
        format!("nosuid,nodev,proto=rdma,port={port}")
    } else {
        "nosuid,nodev,proto=tcp".to_owned()
    };
    let source = format!("{host}:{path}");
    run("mount", &["-t", "nfs", "-o", &opts, &source, mountpoint])
}

pub fn unmount_nfs(mountpoint: &str, confined: bool) -> Result<()> {
    safe_mount_path(mountpoint)?;
    if confined {
        confine_mountpoint(mountpoint, false)?;
    }
    run("umount", &[mountpoint])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("/mnt/greendot/nas1/share", true)]
    #[case("/tank/share", true)]
    #[case("relative/path", false)]
    #[case("/has space", false)]
    #[case("/has,comma", false)]
    #[case("/tra/../versal", false)]
    #[case("/new\nline", false)]
    fn mount_path_safety(#[case] path: &str, #[case] ok: bool) {
        assert_eq!(safe_mount_path(path).is_ok(), ok, "{path:?}");
    }

    #[rstest]
    #[case("10.0.0.5", true)]
    #[case("nas1.example.com", true)]
    #[case("[fd00::1]", true)]
    #[case("", false)]
    #[case("host name", false)]
    #[case("host,x", false)]
    #[case("host/../x", false)]
    #[case("-oremount", false)]
    fn mount_host_safety(#[case] host: &str, #[case] ok: bool) {
        assert_eq!(safe_mount_host(host).is_ok(), ok, "{host:?}");
    }

    /// Shapes a non-root caller may never use, rejected before any filesystem
    /// access (the accepted shape needs a real /mnt/greendot to resolve).
    #[rstest]
    #[case("/etc/sudoers.d")]
    #[case("/mnt/greendot")]
    #[case("/mnt/greendot/nas1")]
    #[case("/mnt/greendot/nas1/share/deeper")]
    #[case("/mnt/greendot/./share")]
    #[case("/mnt/greendotx/nas1/share")]
    fn confined_mountpoint_rejects_other_shapes(#[case] mountpoint: &str) {
        let err = confine_mountpoint(mountpoint, true).unwrap_err();
        assert!(
            err.to_string().contains("only root may"),
            "{mountpoint:?}: {err:#}"
        );
    }

    #[test]
    fn hostnqn_and_hostid_generated_once_and_reused() {
        let dir = std::env::temp_dir().join(format!("gd-priv-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let a = ensure_hostnqn(&dir).unwrap();
        assert!(a.starts_with("nqn.2014-08.org.nvmexpress:uuid:"), "{a}");
        // Well-formed by the shared validator, and stable across calls.
        let nqn = greendot_proto::Nqn::new(a.clone()).unwrap();
        assert_eq!(ensure_hostnqn(&dir).unwrap(), a);
        assert_eq!(
            std::fs::read_to_string(dir.join("hostnqn")).unwrap().trim(),
            a
        );
        // The hostid is the hostnqn's uuid, persisted and then reused as-is.
        let uuid = a.rsplit(':').next().unwrap();
        assert_eq!(ensure_hostid(&dir, &nqn).unwrap(), uuid);
        let other = greendot_proto::Nqn::new("nqn.2014-08.org.nvmexpress:uuid:h1").unwrap();
        assert_eq!(ensure_hostid(&dir, &other).unwrap(), uuid);
        // A non-uuid hostnqn gets a fresh uuid; a corrupt hostid file is refused.
        std::fs::remove_file(dir.join("hostid")).unwrap();
        assert_eq!(ensure_hostid(&dir, &other).unwrap().len(), 36);
        std::fs::write(dir.join("hostid"), "x,y\n").unwrap();
        assert!(ensure_hostid(&dir, &nqn).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Fabrics write + rollback: with a regular file standing in for
    /// /dev/nvme-fabrics and an empty /sys tree, connect writes the option
    /// string, times out waiting for the controller, and reports the ACL
    /// hint. (The 10s wait is real — keep this the only slow test.)
    #[test]
    #[ignore = "10s timeout path — run with --ignored"]
    fn connect_writes_options_and_rolls_back_on_timeout() {
        let root = std::env::temp_dir().join(format!("gd-privc-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("dev")).unwrap();
        std::fs::create_dir_all(root.join("sys/class/nvme")).unwrap();
        std::fs::write(root.join("dev/nvme-fabrics"), "").unwrap();
        let paths = PrivPaths::at(&root);
        let nqn = Nqn::new("nqn.2026-06.io.greendot:vm1").unwrap();
        let host = Nqn::new("nqn.2014-08.org.nvmexpress:uuid:3c3d2f6e-1d2b-4c5a-9e8f-0123456789ab")
            .unwrap();
        let err = connect_nvme(
            &paths,
            &nqn,
            Transport::Rdma,
            "10.0.0.5".parse().unwrap(),
            4420,
            &host,
        )
        .unwrap_err();
        assert!(err.to_string().contains("did not come live"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(root.join("dev/nvme-fabrics")).unwrap(),
            "nqn=nqn.2026-06.io.greendot:vm1,transport=rdma,traddr=10.0.0.5,\
             trsvcid=4420,hostnqn=nqn.2014-08.org.nvmexpress:uuid:3c3d2f6e-1d2b-4c5a-9e8f-0123456789ab,\
             hostid=3c3d2f6e-1d2b-4c5a-9e8f-0123456789ab"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
