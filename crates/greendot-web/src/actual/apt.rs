//! Probe which packages apt can actually install on this host, so the UI only
//! offers a one-click install for packages with a real candidate. Read-only and
//! unprivileged (`apt-cache policy`); used only on Debian/Ubuntu.

use std::collections::HashSet;

/// Packages from `policy_output` that have an install candidate. Parses
/// `apt-cache policy <pkgs…>`: a non-indented line ending in `:` is a package
/// header, and within its block a `Candidate:` line other than `(none)` means
/// installable. Packages apt does not know get no block at all, so they are
/// simply absent from the result.
pub fn parse_available(policy_output: &str) -> HashSet<String> {
    let mut available = HashSet::new();
    let mut current: Option<&str> = None;
    for line in policy_output.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.strip_suffix(':');
        } else if let Some(pkg) = current
            && let Some(candidate) = line.trim().strip_prefix("Candidate:")
            && candidate.trim() != "(none)"
        {
            available.insert(pkg.to_string());
        }
    }
    available
}

/// Subset of `packages` apt can install on this host. Empty input is a no-op;
/// if `apt-cache` can't be run we assume everything is installable rather than
/// hide the install button (this path only runs on Debian/Ubuntu, where
/// `apt-cache` is virtually always present).
pub async fn available(packages: &[String]) -> HashSet<String> {
    if packages.is_empty() {
        return HashSet::new();
    }
    match tokio::process::Command::new("apt-cache")
        .arg("policy")
        .args(packages)
        .output()
        .await
    {
        Ok(out) => parse_available(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => packages.iter().cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_packages_with_a_real_candidate() {
        // Shape of `apt-cache policy nvme-cli held-pkg` — note an unknown package
        // (e.g. nvmetcli on Ubuntu 26.04) produces no block at all on stdout.
        let out = "\
nvme-cli:
  Installed: (none)
  Candidate: 2.4-1
  Version table:
     2.4-1 500
        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
held-pkg:
  Installed: (none)
  Candidate: (none)
  Version table:
";
        let available = parse_available(out);
        assert!(available.contains("nvme-cli"));
        assert!(!available.contains("held-pkg")); // candidate (none)
        assert!(!available.contains("nvmetcli")); // never appeared in output
        assert_eq!(available.len(), 1);
    }
}
