//! Vendor-neutral NIC configuration via iproute2 (`ip`), as tasks. Reads of the
//! same live config are done directly in [`crate::exec`]; the mutating builders
//! live here.

use crate::cmd::TaskSpec;
use greendot_proto::NetdevName;

/// `ip link set dev <netdev> mtu <mtu>` — change an interface's MTU. Generic to
/// every Ethernet NIC; the driver rejects a value the device can't take.
pub fn set_mtu(netdev: &NetdevName, mtu: u32) -> TaskSpec {
    TaskSpec::new(
        "ip",
        [
            "link",
            "set",
            "dev",
            netdev.as_str(),
            "mtu",
            &mtu.to_string(),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_mtu_args() {
        let spec = set_mtu(&NetdevName::new("eth0").unwrap(), 9000);
        assert_eq!(spec.command, "ip");
        assert_eq!(
            spec.args,
            ["link", "set", "dev", "eth0", "mtu", "9000"].map(String::from)
        );
    }
}
