//! The target's `/api/client/v1` JSON API over HTTPS with the certificate
//! pinned by fingerprint. The pin from the connection string *is* the server
//! identity — the verifier checks nothing else about the cert (self-signed,
//! no hostname) — but TLS handshake signatures are still verified, so the
//! bearer token is never sent to a peer that doesn't hold the pinned cert's
//! key. A pairing without a fingerprint means the target serves plain HTTP.

use crate::pairing::Pairing;
use anyhow::{Context, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Deserialize;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;

/// Accepts exactly the certificate whose DER sha256 matches the pin.
#[derive(Debug)]
struct PinnedCert {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = sha2::Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    // Handshake signatures stay fully verified — only the *chain/name* checks
    // are replaced by the pin. Stubbing these to Ok would let anyone replay
    // the pinned cert without its private key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn parse_fingerprint(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        bail!("fingerprint must be 64 hex chars");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .with_context(|| format!("bad hex in fingerprint {hex:?}"))?;
    }
    Ok(out)
}

/// A connected target API endpoint (agent + base URL + bearer token).
pub struct TargetApi {
    agent: ureq::Agent,
    base: String,
    token: String,
}

// ---- reply DTOs (mirror greendot-web's routes/client_api.rs) ----

#[derive(Debug, Deserialize)]
pub struct TargetInfo {
    pub name: String,
    pub api: u32,
    #[allow(dead_code)]
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct Listener {
    pub trtype: String,
    /// `None` = connect to the pairing host (unspecified listen address).
    pub traddr: Option<std::net::IpAddr>,
    pub trsvcid: u16,
}

#[derive(Debug, Deserialize)]
pub struct NvmeExport {
    pub id: i64,
    pub name: String,
    pub nqn: String,
    pub enabled: bool,
    /// Includes `allow_any_host` — the server folds it in.
    pub authorized: bool,
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Deserialize)]
pub struct NfsExport {
    pub id: i64,
    pub path: String,
    pub enabled: bool,
    pub port: u16,
    pub rdma: bool,
    pub authorized: bool,
}

#[derive(Debug, Deserialize)]
pub struct Exports {
    pub nvme: Vec<NvmeExport>,
    pub nfs: Vec<NfsExport>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterReply {
    /// The reconcile task to poll before connecting; `None` = nothing changed.
    pub task_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct TaskInfo {
    pub status: String,
    pub error: Option<String>,
}

impl TargetApi {
    /// Builds the client from a pairing: fingerprint → HTTPS pinned to it,
    /// no fingerprint → plain HTTP (the target has no TLS).
    pub fn connect(pairing: &Pairing) -> Result<TargetApi> {
        let (agent, scheme) = match &pairing.fingerprint {
            Some(fp) => {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .context("rustls protocol versions")?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedCert {
                        fingerprint: parse_fingerprint(fp)?,
                        provider,
                    }))
                    .with_no_client_auth();
                let agent = ureq::builder()
                    .tls_config(Arc::new(tls))
                    .timeout(Duration::from_secs(15))
                    .build();
                (agent, "https")
            }
            None => (
                ureq::builder().timeout(Duration::from_secs(15)).build(),
                "http",
            ),
        };
        Ok(TargetApi {
            agent,
            base: format!("{scheme}://{}/api/client/v1", pairing.host),
            token: pairing.token.clone(),
        })
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let reply = self
            .agent
            .get(&format!("{}{path}", self.base))
            .set("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(map_err)?;
        Ok(reply.into_json()?)
    }

    fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        let reply = self
            .agent
            .post(&format!("{}{path}", self.base))
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(body)
            .map_err(map_err)?;
        Ok(reply.into_json()?)
    }

    pub fn target(&self) -> Result<TargetInfo> {
        let info: TargetInfo = self.get("/target")?;
        if info.api != 1 {
            bail!(
                "target speaks client API v{}, this client only v1",
                info.api
            );
        }
        Ok(info)
    }

    pub fn exports(&self, hostnqn: Option<&str>) -> Result<Exports> {
        match hostnqn {
            Some(h) => self.get(&format!("/exports?hostnqn={h}")),
            None => self.get("/exports"),
        }
    }

    pub fn register_nvme(&self, id: i64, hostnqn: &str) -> Result<RegisterReply> {
        self.post(
            &format!("/exports/nvme/{id}/register"),
            serde_json::json!({ "hostnqn": hostnqn }),
        )
    }

    pub fn register_nfs(&self, id: i64, rw: bool) -> Result<RegisterReply> {
        self.post(
            &format!("/exports/nfs/{id}/register"),
            serde_json::json!({ "rw": rw }),
        )
    }

    /// Polls a register's reconcile task until it finishes (the ACL isn't in
    /// the kernel until then), bounded to ~30 s.
    pub fn wait_task(&self, id: i64) -> Result<()> {
        for _ in 0..60 {
            let task: TaskInfo = self.get(&format!("/tasks/{id}"))?;
            match task.status.as_str() {
                "success" => return Ok(()),
                "failed" => bail!(
                    "target reconcile failed: {}",
                    task.error.unwrap_or_else(|| "unknown".into())
                ),
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
        bail!("target reconcile still running after 30s — check its Tasks page");
    }
}

/// Folds ureq's error into something actionable: 401 means the token is bad
/// or revoked; TLS failures almost always mean the pin no longer matches.
fn map_err(e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(401, _) => {
            anyhow!(
                "target rejected the token (revoked?) — create a new connection string and re-add the target"
            )
        }
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            anyhow!("target returned HTTP {code}: {body}")
        }
        ureq::Error::Transport(t) => anyhow!(
            "could not reach target: {t} (a certificate error means the target's TLS cert changed — re-add the target with a fresh connection string)"
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fingerprint_parsing() {
        assert_eq!(
            super::parse_fingerprint(&"ab".repeat(32)).unwrap(),
            [0xab; 32]
        );
        assert!(super::parse_fingerprint("abcd").is_err());
        assert!(super::parse_fingerprint(&"zz".repeat(32)).is_err());
    }
}
