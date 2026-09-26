//! What an agent needs to dial this cluster, as ONE thing.
//!
//! Dialing a nexus node as an agent takes four values: a CA to trust, a client cert
//! and key to present, and the TLS name to verify the server as. Three are files the
//! mint writes into a bundle directory; the fourth is
//! [`TlsConfig::CLUSTER_SERVER_NAME`], which is not written anywhere — so every
//! client re-declared it, and every client also re-spelled the three filenames. That
//! is how one credential turns into four or five settings a caller has to assemble
//! correctly, with a partial assembly failing at dial time.
//!
//! This module makes the bundle self-describing: the mint writes a manifest naming
//! all four, and a client points at the directory. The producer and the consumer are
//! both here, so the layout has exactly one definition and cannot drift between the
//! side that writes it and the side that reads it.
//!
//! A credential is not a destination: the endpoint stays a separate setting because
//! the node that minted a bundle is not necessarily the node a client talks to, and
//! baking one in would make a credential silently wrong after a move.
//!
//! Nor does it hold a token. A verified agent cert authenticates on its own (see
//! `auth::provider` — an agent cert resolves to its identity with an empty
//! `auth_token`), so an agent needs no `sk-` alongside it. The token plane is a
//! separate credential for callers that have no cert.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::TlsConfig;

/// Filename of the manifest inside an agent bundle directory.
pub const CREDENTIAL_MANIFEST: &str = "credential.json";

/// The manifest format version this build writes and understands.
const CREDENTIAL_VERSION: u32 = 1;

/// The manifest an agent bundle carries — see the module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredential {
    /// Format version. A reader that does not know it refuses the credential
    /// instead of guessing: half-parsed dial material fails later, somewhere less
    /// obvious.
    pub version: u32,
    /// The agent this credential is for.
    ///
    /// A convenience for a client that would otherwise parse X.509 to learn its own
    /// name — the certificate's SAN stays authoritative, and a node derives identity
    /// from the cert alone whatever this field says.
    pub agent: String,
    /// TLS name to verify the server as (never the dialed host or IP).
    pub server_name: String,
    /// CA file to trust, relative to the bundle directory.
    pub ca: String,
    /// Client certificate file to present, relative to the bundle directory.
    pub cert: String,
    /// Client key file to present, relative to the bundle directory.
    pub key: String,
}

/// An agent bundle read off disk: the PEM bytes and the name to verify, ready to
/// hand to a TLS client.
#[derive(Debug, Clone)]
pub struct LoadedCredential {
    /// The agent this credential authenticates as.
    pub agent: String,
    /// TLS name to verify the server as.
    pub server_name: String,
    /// CA certificate (PEM).
    pub ca_pem: Vec<u8>,
    /// Client certificate (PEM).
    pub cert_pem: Vec<u8>,
    /// Client key (PEM).
    pub key_pem: Vec<u8>,
}

impl AgentCredential {
    /// The manifest for an agent whose bundle uses the mint's standard filenames.
    ///
    /// The single definition of that layout: a mint calls this rather than writing
    /// the names itself, so the files it produces and the files a client looks for
    /// are the same list by construction.
    #[must_use]
    pub fn for_bundle(agent: &str) -> Self {
        Self {
            version: CREDENTIAL_VERSION,
            agent: agent.to_string(),
            server_name: TlsConfig::CLUSTER_SERVER_NAME.to_string(),
            ca: "ca.pem".to_string(),
            cert: "agent.pem".to_string(),
            key: "agent-key.pem".to_string(),
        }
    }

    /// Write this manifest into an existing bundle directory.
    ///
    /// # Errors
    ///
    /// When the directory is not writable, naming the path that failed.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<PathBuf> {
        let path = dir.join(CREDENTIAL_MANIFEST);
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Read the manifest and the PEMs it names from a bundle directory.
    ///
    /// Accepts the directory or the manifest file itself, so a caller can pass
    /// whichever path it was handed — the mint prints the directory, and an operator
    /// who copies the file path out of a log gets the same behaviour instead of a
    /// "not a directory" error.
    ///
    /// # Errors
    ///
    /// When the manifest is missing, unreadable, of an unknown version, or names a
    /// file that is not there. Every message names the path involved, because the
    /// usual cause is pointing at the wrong directory and the usual fix is visible
    /// the moment the path is on screen.
    pub fn load(path: &Path) -> Result<LoadedCredential, String> {
        let (dir, manifest_path) = if path.is_dir() {
            (path.to_path_buf(), path.join(CREDENTIAL_MANIFEST))
        } else {
            (
                path.parent().unwrap_or(Path::new(".")).to_path_buf(),
                path.to_path_buf(),
            )
        };
        let raw = std::fs::read(&manifest_path).map_err(|e| {
            format!(
                "read {}: {e} — an agent credential is the directory \
                 `nexusd-cluster auth mint --subject-type agent <name>` printed, \
                 which holds {CREDENTIAL_MANIFEST}",
                manifest_path.display()
            )
        })?;
        let manifest: Self = serde_json::from_slice(&raw)
            .map_err(|e| format!("parse {}: {e}", manifest_path.display()))?;
        if manifest.version != CREDENTIAL_VERSION {
            return Err(format!(
                "{} is version {}, and this build understands version {CREDENTIAL_VERSION} \
                 — use a credential minted by a matching cluster rather than a partially \
                 understood one",
                manifest_path.display(),
                manifest.version,
            ));
        }
        let read = |name: &str, what: &str| {
            let p = dir.join(name);
            std::fs::read(&p).map_err(|e| format!("read {what} {}: {e}", p.display()))
        };
        Ok(LoadedCredential {
            ca_pem: read(&manifest.ca, "CA")?,
            cert_pem: read(&manifest.cert, "client cert")?,
            key_pem: read(&manifest.key, "client key")?,
            agent: manifest.agent,
            server_name: manifest.server_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("ca.pem"), b"ca").unwrap();
        std::fs::write(dir.join("agent.pem"), b"cert").unwrap();
        std::fs::write(dir.join("agent-key.pem"), b"key").unwrap();
        AgentCredential::for_bundle("mac-ai").write_to(dir).unwrap()
    }

    /// The producer's layout and the consumer's expectations are the same list.
    #[test]
    fn a_written_bundle_loads_back_whole() {
        let tmp = tempfile::tempdir().unwrap();
        bundle(tmp.path());

        let loaded = AgentCredential::load(tmp.path()).expect("loads");
        assert_eq!(loaded.agent, "mac-ai");
        assert_eq!(loaded.server_name, TlsConfig::CLUSTER_SERVER_NAME);
        assert_eq!(loaded.ca_pem, b"ca");
        assert_eq!(loaded.cert_pem, b"cert");
        assert_eq!(loaded.key_pem, b"key");
    }

    /// The manifest path works as well as the directory — a caller passes whichever
    /// it was handed.
    #[test]
    fn the_manifest_path_is_accepted_too() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = bundle(tmp.path());
        assert_eq!(
            AgentCredential::load(&manifest).expect("loads").agent,
            "mac-ai"
        );
    }

    /// A version this build does not know is refused, not half-used.
    #[test]
    fn an_unknown_version_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        bundle(tmp.path());
        let mut manifest = AgentCredential::for_bundle("mac-ai");
        manifest.version = CREDENTIAL_VERSION + 1;
        manifest.write_to(tmp.path()).unwrap();

        let err = AgentCredential::load(tmp.path()).expect_err("must refuse");
        assert!(err.contains("version"), "{err}");
    }

    /// A missing PEM names itself and the path, since the usual cause is the wrong
    /// directory.
    #[test]
    fn a_missing_pem_names_the_file_that_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        bundle(tmp.path());
        std::fs::remove_file(tmp.path().join("agent-key.pem")).unwrap();

        let err = AgentCredential::load(tmp.path()).expect_err("must fail");
        assert!(err.contains("client key"), "{err}");
        assert!(err.contains("agent-key.pem"), "{err}");
    }

    /// Pointing at a directory that holds no credential says what a credential is.
    #[test]
    fn a_directory_without_a_manifest_explains_what_one_is() {
        let tmp = tempfile::tempdir().unwrap();
        let err = AgentCredential::load(tmp.path()).expect_err("must fail");
        assert!(err.contains(CREDENTIAL_MANIFEST), "{err}");
        assert!(err.contains("auth mint"), "{err}");
    }
}
