/// Human-readable byte sizes (binary units, one decimal).
pub fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] {
        value /= 1024.0;
        unit = next;
        if value < 1024.0 {
            break;
        }
    }
    format!("{value:.1} {unit}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(0, "0 B")]
    #[case(512, "512 B")]
    #[case(1024, "1.0 KiB")]
    #[case(1536, "1.5 KiB")]
    #[case(10 << 20, "10.0 MiB")]
    #[case(10_737_418_240, "10.0 GiB")]
    #[case(3_298_534_883_328, "3.0 TiB")]
    fn formats_binary_units(#[case] bytes: u64, #[case] expected: &str) {
        assert_eq!(human_bytes(bytes), expected);
    }
}
