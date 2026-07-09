//! The `greendot://` connection-string parser. The string is minted by the
//! target's Client access page (`client_access::connection_string`):
//!
//! ```text
//! greendot://<token>@<host>[:port]/?fp=<sha256-hex-of-DER-leaf-cert>
//! ```
//!
//! `fp` is omitted when the target serves plain HTTP — the client then talks
//! http:// to it (the string and the transport carry the same trust either
//! way).

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub token: String,
    /// `host` or `host:port` of the target's web UI, verbatim.
    pub host: String,
    /// Lowercase sha256 hex of the target's TLS leaf cert; `None` = the
    /// target serves plain HTTP.
    pub fingerprint: Option<String>,
}

impl std::str::FromStr for Pairing {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let rest = s
            .trim()
            .strip_prefix("greendot://")
            .context("not a greendot:// connection string")?;
        let (token, rest) = rest
            .split_once('@')
            .context("missing token (expected greendot://<token>@<host>/...)")?;
        if token.is_empty() || token.contains('/') {
            bail!("malformed token in connection string");
        }
        let (host, query) = match rest.split_once('?') {
            Some((h, q)) => (h.trim_end_matches('/'), Some(q)),
            None => (rest.trim_end_matches('/'), None),
        };
        if host.is_empty() || host.contains('/') {
            bail!("malformed host in connection string");
        }
        let fingerprint = query
            .iter()
            .flat_map(|q| q.split('&'))
            .find_map(|kv| kv.strip_prefix("fp="))
            .map(str::to_owned);
        if let Some(fp) = &fingerprint
            && (fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()))
        {
            bail!("malformed fingerprint {fp:?} (expected 64 hex chars)");
        }
        Ok(Pairing {
            token: token.to_owned(),
            host: host.to_owned(),
            fingerprint: fingerprint.map(|f| f.to_ascii_lowercase()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Pairing;
    use rstest::rstest;

    #[rstest]
    // Canonical string as the target mints it.
    #[case(
        &format!("greendot://gdt_ab@10.0.0.5:8443/?fp={}", "ab".repeat(32)),
        Some(("gdt_ab", "10.0.0.5:8443", Some("ab".repeat(32))))
    )]
    // Whitespace tolerated (terminal copy/paste), fp uppercased by transit.
    #[case(
        &format!("  greendot://gdt_x@box.local/?fp={}\n", "AB".repeat(32)),
        Some(("gdt_x", "box.local", Some("ab".repeat(32))))
    )]
    // Plain-HTTP target: no fp, with and without the trailing slash.
    #[case("greendot://gdt_x@192.168.1.9:8080/", Some(("gdt_x", "192.168.1.9:8080", None)))]
    #[case("greendot://gdt_x@box", Some(("gdt_x", "box", None)))]
    // Unknown query params are ignored, fp still found.
    #[case(
        &format!("greendot://t@h:1/?x=1&fp={}", "cd".repeat(32)),
        Some(("t", "h:1", Some("cd".repeat(32))))
    )]
    // Rejects: wrong scheme, no token, empty token, bad fp length/charset.
    #[case("https://gdt_x@host/", None)]
    #[case("greendot://hostonly:8443/", None)]
    #[case("greendot://@host/", None)]
    #[case("greendot://t@host/?fp=abcd", None)]
    #[case(&format!("greendot://t@host/?fp={}zz", "ab".repeat(31)), None)]
    #[case("greendot://t@/", None)]
    fn parse(#[case] input: &str, #[case] expect: Option<(&str, &str, Option<String>)>) {
        let got: Result<Pairing, _> = input.parse();
        match expect {
            Some((token, host, fingerprint)) => {
                let got = got.unwrap_or_else(|e| panic!("{input:?} must parse: {e:#}"));
                assert_eq!(
                    (got.token.as_str(), got.host.as_str(), got.fingerprint),
                    (token, host, fingerprint),
                    "{input:?}"
                );
            }
            None => assert!(got.is_err(), "{input:?} must be rejected"),
        }
    }
}
