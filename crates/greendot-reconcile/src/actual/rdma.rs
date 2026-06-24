//! RDMA device enumeration from /sys/class/infiniband, mapping each device
//! to its backing netdev and that netdev's IP addresses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaDev {
    pub name: String,
    pub netdev: Option<String>,
    pub active: bool,
    /// IP addresses of the backing netdev — empty when inactive or netdev-less.
    pub addrs: Vec<IpAddr>,
}

/// Whether an nvmet/LIO listen address can actually be served via RDMA.
pub fn addr_served_by_rdma(traddr: &str, devs: &[RdmaDev]) -> bool {
    let Ok(addr) = traddr.parse::<IpAddr>() else {
        return false;
    };
    if addr.is_unspecified() {
        return devs.iter().any(|d| !d.addrs.is_empty());
    }
    devs.iter().any(|d| d.addrs.contains(&addr))
}

/// One live RDMA connection (`rdma resource show cm_id`). This is the only
/// NVMe-oF connection signal on a kernel without CONFIG_NVME_TARGET_DEBUGFS:
/// peer IPs at the RDMA-transport level, with no NQN/hostnqn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdmaPeer {
    /// Local listen address (the target side of the connection).
    pub src_addr: String,
    /// Local listen port — attributes the peer to a transport (4420 → NVMe-oF,
    /// 3260 → iSER). `None` when the tool didn't expose a parseable port.
    pub src_port: Option<u16>,
    /// Remote peer address (the connected client).
    pub dst_addr: String,
    pub state: String,
}

/// Split a `rdma`-reported address that may carry an embedded port: bracketed
/// IPv6 `[::1]:4420`, or IPv4 `10.0.0.5:4420`. A bare IPv6 (no brackets, no
/// port) returns `None` so we don't mistake one of its colons for a port.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        return Some((addr.to_owned(), port.parse().ok()?));
    }
    let (addr, port) = s.rsplit_once(':')?;
    if addr.contains(':') {
        return None; // bare IPv6, no port
    }
    Some((addr.to_owned(), port.parse().ok()?))
}

/// Extract (address, port) from a cm_id entry: prefer a separate numeric port
/// field, else fall back to a port embedded in the address string.
fn addr_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> (String, Option<u16>) {
    let raw = obj
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let port_key = key.replace("addr", "port");
    let port = obj.get(&port_key).and_then(|v| {
        v.as_u64()
            .map(|p| p as u16)
            .or_else(|| v.as_str()?.parse().ok())
    });
    match port {
        Some(p) => (raw, Some(p)),
        None => match split_host_port(&raw) {
            Some((addr, p)) => (addr, Some(p)),
            None => (raw, None),
        },
    }
}

/// Parse `rdma -j resource show cm_id` output into connected peers. Defensive:
/// any shape mismatch yields an empty list (the caller then shows nothing).
pub fn peers_from_json(json: &str) -> Vec<RdmaPeer> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    // `... show cm_id` yields an array; `... show` (all types) yields an object
    // keyed by resource type. Accept either.
    let empty = Vec::new();
    let entries = match &value {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(map) => map.values().find_map(|v| v.as_array()).unwrap_or(&empty),
        _ => &empty,
    };
    entries
        .iter()
        .filter_map(|e| {
            let obj = e.as_object()?;
            let (src_addr, src_port) = addr_field(obj, "src-addr");
            let (dst_addr, _) = addr_field(obj, "dst-addr");
            if dst_addr.is_empty() {
                return None; // no peer ⇒ nothing to show
            }
            Some(RdmaPeer {
                src_addr,
                src_port,
                dst_addr,
                state: obj
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            })
        })
        .collect()
}

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
    use rstest::rstest;

    fn dev(addrs: &[&str]) -> RdmaDev {
        RdmaDev {
            name: "rxe0".into(),
            netdev: Some("eth0".into()),
            active: true,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    #[rstest]
    #[case::exact_match("10.0.0.5", &["10.0.0.5"], true)]
    #[case::wrong_addr("10.0.0.9", &["10.0.0.5"], false)]
    #[case::wildcard_with_dev("0.0.0.0", &["10.0.0.5"], true)]
    #[case::wildcard_addrless_dev("0.0.0.0", &[], false)]
    #[case::not_an_ip("bogus", &["10.0.0.5"], false)]
    fn rdma_address_backing(#[case] traddr: &str, #[case] addrs: &[&str], #[case] ok: bool) {
        assert_eq!(addr_served_by_rdma(traddr, &[dev(addrs)]), ok);
        assert!(
            !addr_served_by_rdma(traddr, &[]),
            "no devices, never served"
        );
    }

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

    #[test]
    fn peers_from_json_parses_array_object_and_embedded_ports() {
        // Array form with separate numeric port fields.
        let peers = peers_from_json(
            r#"[{"state":"CONNECTED","src-addr":"10.0.0.5","src-port":4420,"dst-addr":"10.0.0.9","dst-port":50000}]"#,
        );
        assert_eq!(
            peers,
            vec![RdmaPeer {
                src_addr: "10.0.0.5".into(),
                src_port: Some(4420),
                dst_addr: "10.0.0.9".into(),
                state: "CONNECTED".into(),
            }]
        );

        // Ports embedded in the address string (IPv4 src, bracketed IPv6 dst),
        // no separate port keys; object-wrapped under the resource-type key.
        let peers = peers_from_json(
            r#"{"cm_id":[{"state":"CONNECTED","src-addr":"10.0.0.5:3260","dst-addr":"[fe80::1]:50000"}]}"#,
        );
        assert_eq!(
            peers,
            vec![RdmaPeer {
                src_addr: "10.0.0.5".into(),
                src_port: Some(3260),
                dst_addr: "fe80::1".into(),
                state: "CONNECTED".into(),
            }]
        );

        // Garbage, empty, and portless/peerless entries degrade gracefully.
        assert!(peers_from_json("not json").is_empty());
        assert!(peers_from_json("[]").is_empty());
        assert!(peers_from_json(r#"[{"src-addr":"10.0.0.5:4420"}]"#).is_empty());
        let no_port = peers_from_json(r#"[{"src-addr":"10.0.0.5","dst-addr":"10.0.0.9"}]"#);
        assert_eq!(no_port[0].src_port, None);
    }
}
