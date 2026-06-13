//! Validators for the string newtypes. Conservative by design: these strings
//! become configfs path components and command arguments in a root process.

/// One name component: starts alphanumeric, then alphanumerics plus `_ . : -`.
fn component(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
}

pub(crate) fn dataset_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s.split('/').all(component)
}

pub(crate) fn snap_name(s: &str) -> bool {
    s.len() <= 255 && component(s)
}

pub(crate) fn nqn(s: &str) -> bool {
    s.len() <= 223
        && s.strip_prefix("nqn.").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
        })
}

pub(crate) fn iqn(s: &str) -> bool {
    s.len() <= 223
        && s.strip_prefix("iqn.").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || ".:-".contains(c))
        })
}

pub(crate) fn block_dev(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub(crate) fn device_path(s: &str) -> bool {
    match s.strip_prefix("/dev/zvol/") {
        Some(dataset) => dataset_name(dataset),
        None => s.strip_prefix("/dev/").is_some_and(block_dev),
    }
}

pub(crate) fn netdev(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

pub(crate) fn backstore_name(s: &str) -> bool {
    s.len() <= 63 && component(s)
}

pub(crate) fn part_label(s: &str) -> bool {
    (1..=36).contains(&s.len()) && component(s)
}

pub(crate) fn export_name(s: &str) -> bool {
    // Lowercase so the same name is valid in both NQNs and IQNs.
    s.len() <= 64
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-.".contains(c))
}

pub(crate) fn package_name(s: &str) -> bool {
    // Debian package name: lowercase alnum start, then alnum plus `+ - .`.
    (2..=100).contains(&s.len())
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
}

pub(crate) fn username(s: &str) -> bool {
    s.len() <= 32
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}
