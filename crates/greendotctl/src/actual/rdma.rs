//! RDMA device enumeration from /sys/class/infiniband, mapping each device
//! to its backing netdev and that netdev's IP addresses. The result DTOs
//! (`RdmaDev`, `RdmaPeer`) and the pure `rdma resource` parsers live in the
//! shared protocol crate; only these sysfs readers live here.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

pub use greendot_proto::actual::rdma::*;

pub(crate) fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The backing netdev: rxe devices expose `parent`; RoCE HCAs expose the
/// GID-table netdev under `ports/<n>/gid_attrs/ndevs/0`.
fn backing_netdev(dev_dir: &Path) -> Option<String> {
    read_trimmed(&dev_dir.join("parent"))
        .or_else(|| read_trimmed(&dev_dir.join("ports/1/gid_attrs/ndevs/0")))
}

pub(crate) fn port_active(dev_dir: &Path) -> bool {
    let Ok(ports) = std::fs::read_dir(dev_dir.join("ports")) else {
        return false;
    };
    ports
        .flatten()
        .any(|port| read_trimmed(&port.path().join("state")).is_some_and(|s| s.contains("ACTIVE")))
}

pub fn read(root: &Path, netdev_addrs: &HashMap<String, Vec<IpAddr>>) -> Vec<RdmaDev> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut devs: Vec<RdmaDev> = entries
        .flatten()
        .map(|entry| {
            let dir = entry.path();
            let netdev = backing_netdev(&dir);
            let active = port_active(&dir);
            let addrs = match (&netdev, active) {
                (Some(nd), true) => netdev_addrs.get(nd).cloned().unwrap_or_default(),
                _ => Vec::new(),
            };
            RdmaDev {
                name: entry.file_name().to_string_lossy().into_owned(),
                netdev,
                active,
                addrs,
            }
        })
        .collect();
    devs.sort_by(|a, b| a.name.cmp(&b.name));
    devs
}

/// Live netdev → IP addresses map (excluding loopback).
pub fn netdev_addrs() -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let Ok(ifaddrs) = nix::ifaddrs::getifaddrs() else {
        return map;
    };
    for ifa in ifaddrs {
        let Some(storage) = ifa.address else { continue };
        let addr: Option<IpAddr> = storage
            .as_sockaddr_in()
            .map(|s| IpAddr::V4(s.ip()))
            .or_else(|| storage.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip())));
        if let Some(addr) = addr
            && !addr.is_loopback()
        {
            map.entry(ifa.interface_name).or_default().push(addr);
        }
    }
    map
}

pub fn devices() -> Vec<RdmaDev> {
    read(Path::new("/sys/class/infiniband"), &netdev_addrs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sysfs_fixture_with_rxe_and_hca_and_inactive() {
        let tmp = std::env::temp_dir().join(format!("gd-ib{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // rxe device with `parent`, active port
        std::fs::create_dir_all(tmp.join("rxe-eth0/ports/1")).unwrap();
        std::fs::write(tmp.join("rxe-eth0/parent"), "eth0\n").unwrap();
        std::fs::write(tmp.join("rxe-eth0/ports/1/state"), "4: ACTIVE\n").unwrap();
        // HCA exposing the netdev via gid_attrs, port down
        std::fs::create_dir_all(tmp.join("mlx5_0/ports/1/gid_attrs/ndevs")).unwrap();
        std::fs::write(tmp.join("mlx5_0/ports/1/gid_attrs/ndevs/0"), "enp3s0\n").unwrap();
        std::fs::write(tmp.join("mlx5_0/ports/1/state"), "1: DOWN\n").unwrap();

        let addrs = HashMap::from([
            ("eth0".to_owned(), vec!["10.0.0.5".parse().unwrap()]),
            ("enp3s0".to_owned(), vec!["10.0.1.7".parse().unwrap()]),
        ]);
        let devs = read(&tmp, &addrs);
        assert_eq!(
            devs,
            vec![
                RdmaDev {
                    name: "mlx5_0".into(),
                    netdev: Some("enp3s0".into()),
                    active: false,
                    addrs: vec![], // down port contributes no serving addresses
                },
                RdmaDev {
                    name: "rxe-eth0".into(),
                    netdev: Some("eth0".into()),
                    active: true,
                    addrs: vec!["10.0.0.5".parse().unwrap()],
                },
            ]
        );
        assert_eq!(read(Path::new("/nonexistent"), &addrs), vec![]);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
