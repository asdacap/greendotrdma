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
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("reading /proc/sys/kernel/random/uuid")?;
    let hostnqn = format!("nqn.2014-08.org.nvmexpress:uuid:{}", uuid.trim());
    std::fs::create_dir_all(etc_nvme)
        .with_context(|| format!("creating {}", etc_nvme.display()))?;
    std::fs::write(&path, format!("{hostnqn}\n"))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(hostnqn)
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
    // Every field is a validated newtype or a typed value — no field can
    // carry a comma, so the option string cannot be smuggled into.
    let options = format!(
        "nqn={nqn},transport={},traddr={traddr},trsvcid={trsvcid},hostnqn={hostnqn}",
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

/// A host fit for the `host:path` mount source.
pub fn safe_mount_host(s: &str) -> Result<()> {
    let ok = !s.is_empty()
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

/// Mounts `host:path` at `mountpoint` (created if missing) over NFS —
/// `proto=rdma,port=<port>` or plain TCP. Uses /usr/bin/mount so mount.nfs
/// handles version/addr negotiation.
pub fn mount_nfs(host: &str, path: &str, mountpoint: &str, rdma: bool, port: u16) -> Result<()> {
    safe_mount_host(host)?;
    safe_mount_path(path)?;
    safe_mount_path(mountpoint)?;
    std::fs::create_dir_all(mountpoint).with_context(|| format!("creating {mountpoint}"))?;
    let opts = if rdma {
        format!("proto=rdma,port={port}")
    } else {
        "proto=tcp".to_owned()
    };
    let source = format!("{host}:{path}");
    run("mount", &["-t", "nfs", "-o", &opts, &source, mountpoint])
}

pub fn unmount_nfs(mountpoint: &str) -> Result<()> {
    safe_mount_path(mountpoint)?;
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
    fn mount_host_safety(#[case] host: &str, #[case] ok: bool) {
        assert_eq!(safe_mount_host(host).is_ok(), ok, "{host:?}");
    }

    #[test]
    fn hostnqn_generated_once_and_reused() {
        let dir = std::env::temp_dir().join(format!("gd-priv-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let a = ensure_hostnqn(&dir).unwrap();
        assert!(a.starts_with("nqn.2014-08.org.nvmexpress:uuid:"), "{a}");
        // Well-formed by the shared validator, and stable across calls.
        assert!(greendot_proto::Nqn::new(a.clone()).is_ok());
        assert_eq!(ensure_hostnqn(&dir).unwrap(), a);
        assert_eq!(
            std::fs::read_to_string(dir.join("hostnqn")).unwrap().trim(),
            a
        );
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
        let host = Nqn::new("nqn.2014-08.org.nvmexpress:uuid:h1").unwrap();
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
             trsvcid=4420,hostnqn=nqn.2014-08.org.nvmexpress:uuid:h1"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
