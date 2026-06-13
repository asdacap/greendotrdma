//! GPT partitioning as `sfdisk` CLI tasks. sfdisk re-reads the table itself.

use crate::cmd::TaskSpec;
use greendot_proto::{BlockDev, PartLabel};

fn dev(disk: &BlockDev) -> String {
    format!("/dev/{disk}")
}

fn s(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

/// Writes a brand-new empty GPT — destroys the existing table.
pub fn table_create(disk: &BlockDev) -> TaskSpec {
    TaskSpec::with_stdin("sfdisk", s(&[&dev(disk)]), "label: gpt\n".into())
}

pub fn partition_create(
    disk: &BlockDev,
    start_sector: Option<u64>,
    size_sectors: Option<u64>,
    label: &PartLabel,
) -> TaskSpec {
    let mut fields = Vec::new();
    if let Some(start) = start_sector {
        fields.push(format!("start={start}"));
    }
    if let Some(size) = size_sectors {
        fields.push(format!("size={size}"));
    }
    fields.push(format!("name={label}"));
    let script = format!("{}\n", fields.join(", "));
    TaskSpec::with_stdin("sfdisk", s(&["--append", &dev(disk)]), script)
}

pub fn partition_delete(disk: &BlockDev, number: u32) -> TaskSpec {
    TaskSpec::new("sfdisk", s(&["--delete", &dev(disk), &number.to_string()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn disk() -> BlockDev {
        BlockDev::new("sdb").unwrap()
    }

    #[rstest]
    #[case::full_spec(Some(2048), Some(2097152), "start=2048, size=2097152, name=data\n")]
    #[case::size_only(None, Some(2097152), "size=2097152, name=data\n")]
    #[case::rest_of_disk(None, None, "name=data\n")]
    fn partition_create_script(
        #[case] start: Option<u64>,
        #[case] size: Option<u64>,
        #[case] script: &str,
    ) {
        let spec = partition_create(&disk(), start, size, &PartLabel::new("data").unwrap());
        assert_eq!(spec.command, "sfdisk");
        assert_eq!(spec.args, s(&["--append", "/dev/sdb"]));
        assert_eq!(spec.stdin.as_deref(), Some(script));
    }

    #[test]
    fn table_create_and_delete() {
        let t = table_create(&disk());
        assert_eq!(
            (t.command.as_str(), t.args.clone(), t.stdin.as_deref()),
            ("sfdisk", s(&["/dev/sdb"]), Some("label: gpt\n"))
        );
        let d = partition_delete(&disk(), 3);
        assert_eq!(
            (d.command.as_str(), d.args, d.stdin),
            ("sfdisk", s(&["--delete", "/dev/sdb", "3"]), None)
        );
    }
}
