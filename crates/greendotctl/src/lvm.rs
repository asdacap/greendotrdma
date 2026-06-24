//! LVM mutations as CLI tasks, plus the read commands the web side requests
//! through the helper (LVM reporting needs root). Sizes are passed in bytes with
//! the `B` suffix; LVM rounds up to the physical-extent boundary.

use crate::cmd::TaskSpec;
use greendot_proto::{DevicePath, LvName, LvmReport, VgName};

fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

/// `vgs`/`lvs`/`pvs` as machine-readable JSON in bytes. Run as a task so the web
/// side gets the output stream; it parses the JSON.
pub fn report(what: LvmReport) -> TaskSpec {
    let (cmd, columns) = match what {
        LvmReport::Vgs => ("vgs", "vg_name,vg_size,vg_free,pv_count,lv_count"),
        LvmReport::Lvs => (
            "lvs",
            "vg_name,lv_name,lv_size,lv_attr,pool_lv,data_percent",
        ),
        LvmReport::Pvs => ("pvs", "pv_name,vg_name,pv_size,pv_free"),
    };
    TaskSpec::new(
        cmd,
        s(&[
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            columns,
        ]),
    )
}

/// `vgcreate <name> <dev>…` — also initialises the PVs. No `-f`: a device with a
/// stale signature is refused rather than wiped (cf. `zpool create`).
pub fn vg_create(name: &VgName, devices: &[DevicePath]) -> TaskSpec {
    let mut args = s(&[name.as_str()]);
    args.extend(devices.iter().map(|d| d.to_string()));
    TaskSpec::new("vgcreate", args)
}

pub fn vg_extend(vg: &VgName, device: &DevicePath) -> TaskSpec {
    TaskSpec::new("vgextend", s(&[vg.as_str(), device.as_str()]))
}

/// `vgreduce <vg> <dev>` — removes a PV; refuses one that still holds extents.
pub fn vg_reduce(vg: &VgName, device: &DevicePath) -> TaskSpec {
    TaskSpec::new("vgreduce", s(&[vg.as_str(), device.as_str()]))
}

/// `vgremove <vg>` — no `-f`, so a non-empty VG is refused.
pub fn vg_remove(vg: &VgName) -> TaskSpec {
    TaskSpec::new("vgremove", s(&[vg.as_str()]))
}

/// `lvcreate -y -n <name> -L <size>B <vg>`. `-y` confirms wiping any stale
/// signature on the freshly allocated extents (the helper has no tty).
pub fn lv_create(vg: &VgName, name: &LvName, size: u64) -> TaskSpec {
    TaskSpec::new(
        "lvcreate",
        s(&[
            "-y",
            "-n",
            name.as_str(),
            "-L",
            &format!("{size}B"),
            vg.as_str(),
        ]),
    )
}

pub fn thin_pool_create(vg: &VgName, name: &LvName, size: u64) -> TaskSpec {
    TaskSpec::new(
        "lvcreate",
        s(&[
            "-y",
            "--type",
            "thin-pool",
            "-L",
            &format!("{size}B"),
            "-n",
            name.as_str(),
            vg.as_str(),
        ]),
    )
}

pub fn thin_lv_create(vg: &VgName, pool: &LvName, name: &LvName, virtual_size: u64) -> TaskSpec {
    TaskSpec::new(
        "lvcreate",
        s(&[
            "-y",
            "--type",
            "thin",
            "--thinpool",
            pool.as_str(),
            "-V",
            &format!("{virtual_size}B"),
            "-n",
            name.as_str(),
            vg.as_str(),
        ]),
    )
}

/// Grow an LV with `lvextend`. Growing never prompts; a smaller size errors out.
pub fn lv_resize(vg: &VgName, name: &LvName, new_size: u64) -> TaskSpec {
    TaskSpec::new(
        "lvextend",
        s(&["-L", &format!("{new_size}B"), &format!("{vg}/{name}")]),
    )
}

/// Shrink an LV with `lvreduce -f`. Destructive; the UI gates it behind a confirm.
pub fn lv_shrink(vg: &VgName, name: &LvName, new_size: u64) -> TaskSpec {
    TaskSpec::new(
        "lvreduce",
        s(&["-f", "-L", &format!("{new_size}B"), &format!("{vg}/{name}")]),
    )
}

pub fn lv_rename(vg: &VgName, name: &LvName, new_name: &LvName) -> TaskSpec {
    TaskSpec::new(
        "lvrename",
        s(&[vg.as_str(), name.as_str(), new_name.as_str()]),
    )
}

/// `lvremove -y <vg>/<lv>` — `-y` because lvremove prompts by default.
pub fn lv_delete(vg: &VgName, name: &LvName) -> TaskSpec {
    TaskSpec::new("lvremove", s(&["-y", &format!("{vg}/{name}")]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn vg() -> VgName {
        VgName::new("vg0").unwrap()
    }

    fn lv(name: &str) -> LvName {
        LvName::new(name).unwrap()
    }

    fn dp(s: &str) -> DevicePath {
        DevicePath::new(s).unwrap()
    }

    fn assert_spec(spec: TaskSpec, cmd: &str, args: &[&str]) {
        assert_eq!(spec.command, cmd);
        assert_eq!(spec.args, s(args));
        assert_eq!(spec.stdin, None);
    }

    #[rstest]
    #[case::vgs(LvmReport::Vgs, "vgs", "vg_name,vg_size,vg_free,pv_count,lv_count")]
    #[case::lvs(
        LvmReport::Lvs,
        "lvs",
        "vg_name,lv_name,lv_size,lv_attr,pool_lv,data_percent"
    )]
    #[case::pvs(LvmReport::Pvs, "pvs", "pv_name,vg_name,pv_size,pv_free")]
    fn report_args(#[case] what: LvmReport, #[case] cmd: &str, #[case] columns: &str) {
        assert_spec(
            report(what),
            cmd,
            &[
                "--reportformat",
                "json",
                "--units",
                "b",
                "--nosuffix",
                "-o",
                columns,
            ],
        );
    }

    #[test]
    fn vg_ops_args() {
        assert_spec(
            vg_create(&vg(), &[dp("/dev/sdb"), dp("/dev/sdc")]),
            "vgcreate",
            &["vg0", "/dev/sdb", "/dev/sdc"],
        );
        assert_spec(
            vg_extend(&vg(), &dp("/dev/sdd")),
            "vgextend",
            &["vg0", "/dev/sdd"],
        );
        assert_spec(
            vg_reduce(&vg(), &dp("/dev/sdd")),
            "vgreduce",
            &["vg0", "/dev/sdd"],
        );
        assert_spec(vg_remove(&vg()), "vgremove", &["vg0"]);
        // No forced device wipe / VG removal.
        assert!(
            !vg_create(&vg(), &[dp("/dev/sdb")])
                .args
                .iter()
                .any(|a| a == "-f" || a == "-y")
        );
        assert!(!vg_remove(&vg()).args.iter().any(|a| a == "-f"));
    }

    #[test]
    fn lv_create_args() {
        assert_spec(
            lv_create(&vg(), &lv("data"), 10 << 30),
            "lvcreate",
            &["-y", "-n", "data", "-L", "10737418240B", "vg0"],
        );
        assert_spec(
            thin_pool_create(&vg(), &lv("pool0"), 100 << 30),
            "lvcreate",
            &[
                "-y",
                "--type",
                "thin-pool",
                "-L",
                "107374182400B",
                "-n",
                "pool0",
                "vg0",
            ],
        );
        assert_spec(
            thin_lv_create(&vg(), &lv("pool0"), &lv("vm1"), 20 << 30),
            "lvcreate",
            &[
                "-y",
                "--type",
                "thin",
                "--thinpool",
                "pool0",
                "-V",
                "21474836480B",
                "-n",
                "vm1",
                "vg0",
            ],
        );
    }

    #[test]
    fn lv_mutation_args() {
        assert_spec(
            lv_resize(&vg(), &lv("data"), 20 << 30),
            "lvextend",
            &["-L", "21474836480B", "vg0/data"],
        );
        assert_spec(
            lv_shrink(&vg(), &lv("data"), 5 << 30),
            "lvreduce",
            &["-f", "-L", "5368709120B", "vg0/data"],
        );
        assert_spec(
            lv_rename(&vg(), &lv("old"), &lv("new")),
            "lvrename",
            &["vg0", "old", "new"],
        );
        assert_spec(
            lv_delete(&vg(), &lv("data")),
            "lvremove",
            &["-y", "vg0/data"],
        );
    }
}
