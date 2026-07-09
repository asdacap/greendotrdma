//! The client-side Diagnose checklist — the initiator mirror of the target's
//! diagnose pages. Each check is a `Criterion { label, ok, detail }` (the
//! same shape the web renders), ordered so the first ✗ is usually the fix:
//! privilege broker → kernel plumbing → RDMA hardware → target reachability
//! → registration → the live connection itself.

use crate::status::{self, SysRoots};
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct Criterion {
    pub label: &'static str,
    pub ok: bool,
    pub detail: String,
}

pub fn check(label: &'static str, ok: bool, detail: impl Into<String>) -> Criterion {
    Criterion {
        label,
        ok,
        detail: detail.into(),
    }
}

/// An RDMA device with an ACTIVE port exists — required for every green dot.
pub fn rdma_device_check(sys: &SysRoots) -> Criterion {
    let devices = status::active_rdma_devices(&sys.sys_class_infiniband);
    check(
        "RDMA device with an active port",
        !devices.is_empty(),
        if devices.is_empty() {
            "none under /sys/class/infiniband — no RDMA NIC, port down, or RoCE off \
             (the target's Settings page can enable Soft-RoCE on plain NICs)"
                .to_owned()
        } else {
            devices.join(", ")
        },
    )
}

/// The NVMe-oF plumbing needed before a fabrics connect can even start.
pub fn nvme_path_checks(sys_root: &Path, sys: &SysRoots) -> Vec<Criterion> {
    let fabrics = sys_root.join("dev/nvme-fabrics");
    let mut checks = vec![check(
        "/dev/nvme-fabrics present",
        fabrics.exists(),
        if fabrics.exists() {
            String::new()
        } else {
            "modprobe nvme-fabrics (plus nvme-rdma / nvme-tcp)".to_owned()
        },
    )];
    for (module, hint) in [
        (
            "nvme_rdma",
            "modprobe nvme-rdma — required for RDMA connects",
        ),
        ("nvme_tcp", "modprobe nvme-tcp — required for TCP fallback"),
    ] {
        let loaded = status::module_loaded(&sys.sys_module, module);
        checks.push(check(
            match module {
                "nvme_rdma" => "nvme_rdma module loaded",
                _ => "nvme_tcp module loaded",
            },
            loaded,
            if loaded { "" } else { hint },
        ));
    }
    checks.push(rdma_device_check(sys));
    checks
}

/// The NFS plumbing: mount.nfs (nfs-common) and the RDMA transport module.
pub fn nfs_path_checks(sys_root: &Path, sys: &SysRoots) -> Vec<Criterion> {
    let mount_nfs = ["sbin/mount.nfs", "usr/sbin/mount.nfs"]
        .iter()
        .any(|p| sys_root.join(p).exists());
    let rpcrdma = status::module_loaded(&sys.sys_module, "rpcrdma")
        || status::module_loaded(&sys.sys_module, "xprtrdma");
    vec![
        check(
            "mount.nfs installed",
            mount_nfs,
            if mount_nfs { "" } else { "install nfs-common" },
        ),
        check(
            "rpcrdma module loaded",
            rpcrdma,
            if rpcrdma {
                ""
            } else {
                "modprobe rpcrdma — required for NFS-over-RDMA (TCP mounts work without)"
            },
        ),
        rdma_device_check(sys),
    ]
}

/// TCP reachability of `host[:port]` (default port when none), as a routing
/// proxy — it proves IP reachability, not that RDMA traffic passes.
pub fn dial_check(label: &'static str, host: &str, default_port: u16) -> Criterion {
    let hostport = if host
        .rsplit(':')
        .next()
        .is_some_and(|p| p.parse::<u16>().is_ok())
        && (host.contains("]:") || host.matches(':').count() == 1)
    {
        host.to_owned()
    } else {
        format!("{host}:{default_port}")
    };
    let result = std::net::ToSocketAddrs::to_socket_addrs(&hostport.as_str())
        .map_err(|e| e.to_string())
        .and_then(|mut addrs| addrs.next().ok_or_else(|| "no address".to_owned()))
        .and_then(|addr| {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map(|_| addr)
                .map_err(|e| format!("{addr}: {e}"))
        });
    match result {
        Ok(addr) => check(label, true, format!("reached {addr}")),
        Err(e) => check(label, false, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_over_fixture_roots() {
        let root = std::env::temp_dir().join(format!("gd-diag-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        // Empty tree: everything fails with actionable hints.
        std::fs::create_dir_all(&root).unwrap();
        let sys = SysRoots::at(&root);
        let nvme = nvme_path_checks(&root, &sys);
        assert_eq!(nvme.len(), 4);
        assert!(nvme.iter().all(|c| !c.ok), "{nvme:?}");
        assert!(nvme[0].detail.contains("modprobe nvme-fabrics"));
        let nfs = nfs_path_checks(&root, &sys);
        assert!(nfs.iter().all(|c| !c.ok));
        assert!(nfs[0].detail.contains("nfs-common"));

        // Populated tree: all green.
        std::fs::create_dir_all(root.join("dev")).unwrap();
        std::fs::write(root.join("dev/nvme-fabrics"), "").unwrap();
        for m in ["nvme_rdma", "nvme_tcp", "rpcrdma"] {
            std::fs::create_dir_all(root.join("sys/module").join(m)).unwrap();
        }
        std::fs::create_dir_all(root.join("sbin")).unwrap();
        std::fs::write(root.join("sbin/mount.nfs"), "").unwrap();
        let p = root.join("sys/class/infiniband/rxe0/ports/1");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("state"), "4: ACTIVE").unwrap();
        let sys = SysRoots::at(&root);
        assert!(nvme_path_checks(&root, &sys).iter().all(|c| c.ok));
        assert!(nfs_path_checks(&root, &sys).iter().all(|c| c.ok));
        let rdma = rdma_device_check(&sys);
        assert_eq!(rdma.detail, "rxe0");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dial_check_reports_reachability() {
        // A listening socket on localhost: reachable, and the port embedded
        // in the host string wins over the default.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let c = dial_check("target reachable", &format!("127.0.0.1:{port}"), 1);
        assert!(c.ok, "{c:?}");
        drop(listener);
        // A port nothing listens on: refused, detail carries the error.
        let c = dial_check("target reachable", &format!("127.0.0.1:{port}"), 1);
        assert!(!c.ok);
        assert!(!c.detail.is_empty());
    }
}
