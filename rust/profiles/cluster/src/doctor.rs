//! `nexusd-cluster doctor`: a read-only health audit of a stopped daemon's
//! data directory, aligned by construction with the checks daemon boot runs.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use x509_parser::prelude::{FromDer, X509Certificate};

/// A Node certificate this close to expiry is reported before it can fail a
/// boot; renewal (`enroll`) is an operator action.
const CERTIFICATE_EXPIRY_WARNING_DAYS: i64 = 14;

/// One-shot health audit of a stopped daemon's data directory. Prints a
/// single-screen summary with alarms that name the historical operator
/// failure modes, and exits 2 when any alarm fires (for CI and watch loops).
///
/// The Node certificate section reads `tls/node.pem` through the same
/// identity check boot applies and compares the Node it names with the
/// persisted `.node_id`:
///
///   * `NODE_ID_MISMATCH` / `NODE_ID_MISSING` — the certificate names another
///     Node than the persisted one, or none is persisted; boot refuses.
///   * `CERT_NOT_YET_VALID` / `CERT_EXPIRED` — outside its validity window.
///   * `CERT_UNTRUSTED` — not a current Node leaf of the bundled cluster CA.
///   * `CERT_EXPIRING` (warning) — expires within
///     [`CERTIFICATE_EXPIRY_WARNING_DAYS`].
///
/// Each zone section reads the persisted ConfState + HardState +
/// last_log_index directly from redb (no driver, no async runtime, no kernel
/// attachment):
///
///   * `STALE_LOG` — log_last_index = 0 but ConfState non-empty.
///     The half-installed state that wedged the Mac↔Win L1 smoke
///     for 8 h.  Use the same `check_zone_resumable_from_indices`
///     invariant `bootstrap_or_join_zone` Branch 1 uses, so doctor
///     and daemon-boot stay aligned by construction.
///
/// `--data-dir` is the same path passed to `nexusd-cluster
/// --data-dir`.  Subdirectories that contain a `raft/raft.redb` file
/// are treated as zones; others are skipped.  redb's exclusive lock
/// means the daemon must be stopped first — the failure mode
/// otherwise is a clear "could not open zone storage" error per zone.
pub(super) fn run(data_dir: &Path, zone_filter: Option<&str>) -> Result<()> {
    if !data_dir.exists() {
        return Err(anyhow::anyhow!(
            "doctor: --data-dir {} does not exist",
            data_dir.display()
        ));
    }
    let zones = discover_zones(data_dir, zone_filter)?;
    let total = zones.len();
    println!("# Doctor — {} zone(s) under {}", total, data_dir.display());
    println!();
    let certificate_alarms = audit_node_certificate(data_dir, &mut std::io::stdout().lock())?;
    let zone_alarms = audit_zones(data_dir, zone_filter, zones)?;
    println!(
        "Summary: {certificate_alarms} node-certificate alarm(s); \
         {zone_alarms} alarmed / {total} total zone(s).  {}",
        if certificate_alarms + zone_alarms == 0 {
            "All checks look healthy."
        } else {
            "See the RECOVERY hints above."
        }
    );
    if certificate_alarms + zone_alarms > 0 {
        // Non-zero exit for scripted use (CI alarms, watch loops).
        std::process::exit(2);
    }
    Ok(())
}

/// Audit the Node certificate against the persisted Node ID. The verdict is the
/// boot check itself ([`nexus_raft::transport::local_node_identity`]); the
/// validity window and CA facts around it explain a refusal. Returns the
/// number of alarms written.
fn audit_node_certificate(data_dir: &Path, out: &mut impl Write) -> Result<usize> {
    let tls_dir = data_dir.join("tls");
    let (cert_path, ca_path) = (tls_dir.join("node.pem"), tls_dir.join("ca.pem"));
    writeln!(out, "## node certificate")?;
    let Some(cert_pem) = read_optional(&cert_path)? else {
        writeln!(
            out,
            "  none at {} (a --no-tls node, or one not yet enrolled)\n",
            cert_path.display()
        )?;
        return Ok(0);
    };
    writeln!(out, "  certificate = {}", cert_path.display())?;
    let mut findings = Findings::default();
    let leaf_der = lib::transport_primitives::first_certificate_der(&cert_pem, "Node").ok();
    let Some((_, leaf)) = leaf_der
        .as_deref()
        .and_then(|der| X509Certificate::from_der(der).ok())
    else {
        findings.alarms.push(format!(
            "CERT_UNTRUSTED: {} holds no X.509 certificate",
            cert_path.display()
        ));
        return findings.write(out, data_dir);
    };

    // The subject CN is display only (a hostname or the Node ID); the Node is
    // the identity URI SAN the transport authenticates peers by.
    writeln!(out, "  subject     = {}", leaf.subject())?;
    let named = lib::transport_primitives::node_identity_from_x509(&leaf);
    match &named {
        Ok((zone, node)) => writeln!(
            out,
            "  names       = {}",
            lib::transport_primitives::node_identity_uri(zone, *node)
        )?,
        Err(error) => writeln!(out, "  names       = no Node identity ({error})")?,
    }
    let persisted = nexus_raft::distributed_coordinator::read_node_id(data_dir);
    match &persisted {
        Ok(Some(node)) => writeln!(out, "  node_id     = {node}")?,
        Ok(None) => writeln!(out, "  node_id     = none persisted")?,
        Err(error) => writeln!(out, "  node_id     = unreadable ({error})")?,
    }

    let validity = leaf.validity();
    let (start, end) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    writeln!(
        out,
        "  validity    = {} .. {}",
        validity.not_before, validity.not_after
    )?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    if now < start {
        findings.clock_skew = true;
        findings.alarms.push(format!(
            "CERT_NOT_YET_VALID: valid only from {}, {}s ahead of this host's clock",
            validity.not_before,
            start - now
        ));
    } else if now > end {
        findings
            .alarms
            .push(format!("CERT_EXPIRED: expired {}", validity.not_after));
    } else if end - now < CERTIFICATE_EXPIRY_WARNING_DAYS * 86_400 {
        findings.warnings.push(format!(
            "CERT_EXPIRING: expires in {} day(s)",
            (end - now) / 86_400
        ));
    }

    match read_optional(&ca_path)? {
        None => findings.alarms.push(format!(
            "CERT_UNTRUSTED: no cluster CA at {}",
            ca_path.display()
        )),
        Some(ca_pem) => {
            let verdict = nexus_raft::transport::local_node_identity(&cert_pem, &ca_pem);
            if !write_authority(out, &leaf, &ca_pem)? {
                findings.alarms.push(format!(
                    "CERT_UNTRUSTED: the CA at {} does not sign this certificate",
                    ca_path.display()
                ));
            } else if let (Err(error), true) = (verdict, findings.alarms.is_empty()) {
                // The boot check; a validity alarm above already explains its refusal.
                findings.alarms.push(format!("CERT_UNTRUSTED: {error}"));
            }
        }
    }

    match (named, persisted) {
        (Ok((_, named)), Ok(Some(persisted))) if named != persisted => {
            findings.alarms.push(format!(
                "NODE_ID_MISMATCH: the certificate names Node {named}, but this data directory's \
             Node ID is {persisted}; the daemon refuses to boot"
            ))
        }
        (Ok((_, named)), Ok(None)) => findings.alarms.push(format!(
            "NODE_ID_MISSING: the certificate names Node {named}, but no Node ID is \
             persisted; boot would mint one it does not name"
        )),
        (_, Err(error)) => findings.alarms.push(format!("NODE_ID_UNREADABLE: {error}")),
        _ => {}
    }
    findings.write(out, data_dir)
}

#[derive(Default)]
struct Findings {
    alarms: Vec<String>,
    warnings: Vec<String>,
    /// The only alarm a re-issued certificate cannot cure.
    clock_skew: bool,
}

impl Findings {
    /// Write warnings, alarms and their remedies; returns the alarm count.
    fn write(self, out: &mut impl Write, data_dir: &Path) -> Result<usize> {
        for warning in &self.warnings {
            writeln!(out, "  WARN   {warning}")?;
        }
        for alarm in &self.alarms {
            writeln!(out, "  ALARM  {alarm}")?;
        }
        if self.clock_skew {
            writeln!(
                out,
                "  RECOVERY: synchronize this host's clock with its issuer's (NTP)"
            )?;
        }
        if !self.warnings.is_empty() || self.alarms.len() > usize::from(self.clock_skew) {
            writeln!(
                out,
                "  RECOVERY: re-enroll so the CA holder re-issues this Node's certificate for \
                 its persisted Node ID:\n  \
                 nexusd-cluster enroll <founder_host:port> <join_token> --data-dir {}",
                data_dir.display()
            )?;
        }
        if self.alarms.is_empty() && self.warnings.is_empty() {
            writeln!(out, "  OK")?;
        }
        writeln!(out)?;
        Ok(self.alarms.len())
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Report which CA the bundle carries, in the form operator grants pin, and
/// whether it signs the Node certificate.
fn write_authority(
    out: &mut impl Write,
    leaf: &X509Certificate<'_>,
    ca_pem: &[u8],
) -> Result<bool> {
    let ca_der = lib::transport_primitives::first_certificate_der(ca_pem, "cluster CA").ok();
    let Some((_, ca)) = ca_der
        .as_deref()
        .and_then(|der| X509Certificate::from_der(der).ok())
    else {
        writeln!(out, "  ca          = no X.509 certificate in the CA bundle")?;
        return Ok(false);
    };
    let signed = lib::transport_primitives::authorship::cert_signed_by(leaf, &ca);
    writeln!(
        out,
        "  ca          = {} sha256={} ({} this certificate; valid until {})",
        ca.subject(),
        super::certificate_sha256_hex(ca_pem)?,
        if signed { "signs" } else { "does NOT sign" },
        ca.validity().not_after
    )?;
    Ok(signed)
}

/// Candidate zones: any subdir whose `raft/raft.redb` file exists. Same shape
/// `ZoneRaftRegistry::enumerate_*` uses at boot, without instantiating the
/// live state machine.
fn discover_zones(data_dir: &Path, zone_filter: Option<&str>) -> Result<Vec<(String, PathBuf)>> {
    let mut zones: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(data_dir)
        .with_context(|| format!("doctor: read_dir({})", data_dir.display()))?
    {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let raft_dir = entry.path().join("raft");
        if !raft_dir.join("raft.redb").exists() {
            continue;
        }
        if let Some(filter) = zone_filter {
            if name != filter {
                continue;
            }
        }
        zones.push((name, raft_dir));
    }
    zones.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(zones)
}

/// Audit each zone's persisted Raft state; returns the number alarmed.
fn audit_zones(
    data_dir: &Path,
    zone_filter: Option<&str>,
    zones: Vec<(String, PathBuf)>,
) -> Result<usize> {
    use nexus_raft::raft::RaftStorage;

    if zones.is_empty() {
        if let Some(filter) = zone_filter {
            println!(
                "doctor: no zone '{filter}' found under {}",
                data_dir.display()
            );
        } else {
            println!(
                "doctor: no zones found under {} (looking for <zone>/raft/raft.redb)",
                data_dir.display()
            );
        }
        println!();
        return Ok(0);
    }

    let mut alarmed = 0usize;
    for (zone_id, raft_dir) in zones {
        let storage = match RaftStorage::open(&raft_dir) {
            Ok(s) => s,
            Err(e) => {
                println!("## zone '{zone_id}'");
                println!("  ALARM  STORAGE_LOCKED: could not open raft storage at {} — is the daemon still running?  {e}", raft_dir.display());
                println!();
                alarmed += 1;
                continue;
            }
        };
        // RaftStorage exposes the storage state via inherent _impl
        // methods (the raft-rs `Storage` trait methods all delegate
        // to these); using them directly keeps the trait out of
        // scope here.
        let state = storage
            .initial_state_impl()
            .map_err(|e| anyhow::anyhow!("zone '{zone_id}': initial_state: {e:?}"))?;
        let last_log_index = storage
            .last_index_impl()
            .map_err(|e| anyhow::anyhow!("zone '{zone_id}': last_index: {e:?}"))?;
        let first_log_index = storage
            .first_index_impl()
            .map_err(|e| anyhow::anyhow!("zone '{zone_id}': first_index: {e:?}"))?;

        println!("## zone '{zone_id}'");
        println!(
            "  voters     = {:?}",
            state.conf_state.voters.iter().collect::<Vec<_>>()
        );
        println!(
            "  learners   = {:?}",
            state.conf_state.learners.iter().collect::<Vec<_>>()
        );
        println!("  term       = {}", state.hard_state.term);
        println!("  commit     = {}", state.hard_state.commit);
        println!("  log_first  = {first_log_index}");
        println!("  log_last   = {last_log_index}");

        // Cross-check against the same invariant `bootstrap_or_join_zone`
        // Branch 1 uses — single SSOT for "resumable state".
        if let Err(reason) =
            nexus_raft::distributed_coordinator::check_zone_resumable_from_indices(last_log_index)
        {
            alarmed += 1;
            println!(
                "  ALARM  STALE_LOG: {reason}\n  \
                 RECOVERY: stop the daemon, then either\n  \
                 (a) run `nexusd-cluster join <leader_node_id>@<leader_addr> {zone_id} \
                 /<mount> --data-dir <data_dir> --no-tls` against the leader, then restart, or\n  \
                 (b) `rm -rf {raft_dir_parent}` (this zone only) and restart in static mode.",
                raft_dir_parent = raft_dir
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| zone_id.clone()),
            );
        } else {
            println!("  OK");
        }
        println!();
    }
    Ok(alarmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{generate_node_cert, generate_zone_ca};
    use std::time::{Duration, SystemTime};

    const DAY: Duration = Duration::from_secs(86_400);

    /// A stopped data directory: persisted Node ID plus its TLS bundle.
    fn data_dir(node_id: u64, cert: &[u8], ca: &[u8]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(".node_id"), node_id.to_be_bytes()).unwrap();
        let tls = directory.path().join("tls");
        std::fs::create_dir_all(&tls).unwrap();
        std::fs::write(tls.join("node.pem"), cert).unwrap();
        std::fs::write(tls.join("ca.pem"), ca).unwrap();
        directory
    }

    fn audit(directory: &tempfile::TempDir) -> (usize, String) {
        let mut out = Vec::new();
        let alarms = audit_node_certificate(directory.path(), &mut out).unwrap();
        (alarms, String::from_utf8(out).unwrap())
    }

    /// A CA-signed Node certificate with an explicit validity window.
    fn windowed(
        node: u64,
        ca: &[u8],
        ca_key: &[u8],
        from: SystemTime,
        until: SystemTime,
    ) -> Vec<u8> {
        let issuer = rcgen::Issuer::from_ca_cert_pem(
            std::str::from_utf8(ca).unwrap(),
            rcgen::KeyPair::from_pem(std::str::from_utf8(ca_key).unwrap()).unwrap(),
        )
        .unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            lib::transport_primitives::node_identity_uri("root", node)
                .try_into()
                .unwrap(),
        )];
        (params.not_before, params.not_after) = (from.into(), until.into());
        let key = rcgen::KeyPair::generate().unwrap();
        params.signed_by(&key, &issuer).unwrap().pem().into_bytes()
    }

    #[test]
    fn a_current_certificate_for_the_persisted_node_is_healthy_in_either_cn_form() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (numeric, _) = generate_node_cert(7, "root", &ca, &ca_key, &[], None).unwrap();
        let (alarms, report) = audit(&data_dir(7, &numeric, &ca));
        assert_eq!(alarms, 0, "{report}");
        assert!(report.contains("CN=nexus-zone-root-node-7\n"), "{report}");
        // A founder's bootstrap certificate names its host in the CN.
        let host = Some("DESKTOP-K2PHFNR");
        let (cert, _) = generate_node_cert(7, "root", &ca, &ca_key, &[], host).unwrap();
        let (alarms, report) = audit(&data_dir(7, &cert, &ca));
        assert_eq!(alarms, 0, "{report}");
        assert!(
            report.contains("CN=nexus-zone-root-node-DESKTOP-K2PHFNR\n"),
            "{report}"
        );
        assert!(
            report.contains("names       = nexus://zone/root/node/7\n"),
            "{report}"
        );
        assert!(report.contains("node_id     = 7\n"), "{report}");
        let pinned = super::super::certificate_sha256_hex(&ca).unwrap();
        assert!(
            report.contains(&format!("sha256={pinned} (signs this")),
            "{report}"
        );
        assert!(
            report.contains("  OK\n") && !report.contains("RECOVERY"),
            "{report}"
        );
    }

    #[test]
    fn a_certificate_naming_another_node_is_diagnosed_with_the_reenroll_remedy() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert, _) =
            generate_node_cert(6272818444033277711, "root", &ca, &ca_key, &[], None).unwrap();
        let directory = data_dir(6536933648025587040, &cert, &ca);
        let (alarms, report) = audit(&directory);
        assert_eq!(alarms, 1, "{report}");
        assert!(
            report.contains(
                "ALARM  NODE_ID_MISMATCH: the certificate names Node 6272818444033277711, but \
                 this data directory's Node ID is 6536933648025587040"
            ),
            "{report}"
        );
        let remedy = format!(
            "nexusd-cluster enroll <founder_host:port> <join_token> --data-dir {}",
            directory.path().display()
        );
        assert!(report.contains(&remedy), "{report}");
    }

    #[test]
    fn the_validity_window_and_the_issuing_ca_are_diagnosed() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let now = SystemTime::now();

        let expired = windowed(7, &ca, &ca_key, now - 100 * DAY, now - DAY);
        let (alarms, report) = audit(&data_dir(7, &expired, &ca));
        assert_eq!(alarms, 1, "{report}");
        assert!(report.contains("ALARM  CERT_EXPIRED: expired "), "{report}");
        assert!(report.contains("nexusd-cluster enroll"), "{report}");

        // Issued by a CA host whose clock runs two minutes ahead of this one.
        let ahead = windowed(7, &ca, &ca_key, now + Duration::from_secs(120), now + DAY);
        let (alarms, report) = audit(&data_dir(7, &ahead, &ca));
        assert_eq!(alarms, 1, "{report}");
        assert!(
            report.contains("ALARM  CERT_NOT_YET_VALID: valid only from "),
            "{report}"
        );
        assert!(
            report.contains("RECOVERY: synchronize this host's clock"),
            "{report}"
        );
        assert!(!report.contains("nexusd-cluster enroll"), "{report}");

        let expiring = windowed(7, &ca, &ca_key, now - DAY, now + 3 * DAY);
        let (alarms, report) = audit(&data_dir(7, &expiring, &ca));
        assert_eq!(alarms, 0, "{report}");
        assert!(
            report.contains("WARN   CERT_EXPIRING: expires in 2 day(s)"),
            "{report}"
        );
        assert!(report.contains("nexusd-cluster enroll"), "{report}");

        let (foreign, foreign_key) = generate_zone_ca("root").unwrap();
        let (outsider, _) =
            generate_node_cert(7, "root", &foreign, &foreign_key, &[], None).unwrap();
        let (alarms, report) = audit(&data_dir(7, &outsider, &ca));
        assert_eq!(alarms, 1, "{report}");
        assert!(
            report.contains("ALARM  CERT_UNTRUSTED: the CA at ")
                && report.contains("does not sign this certificate"),
            "{report}"
        );
        assert!(
            report.contains("(does NOT sign this certificate"),
            "{report}"
        );
    }

    #[test]
    fn a_node_without_a_certificate_has_nothing_to_audit() {
        let directory = tempfile::tempdir().unwrap();
        let (alarms, report) = audit(&directory);
        assert_eq!(alarms, 0);
        assert!(report.contains("  none at "), "{report}");
    }
}
