//! Who is allowed to call this daemon, and when serving nobody-in-particular
//! is legal.
//!
//! ## The invariant
//!
//! > **Serving without authentication is legal only on loopback. Binding a
//! > reachable address requires either an `sk-` credential policy or mTLS.**
//!
//! A daemon on `127.0.0.1` with no auth is the standard trusted-local-backend
//! pattern — a plaintext socket inside one trust domain, the same shape as a
//! Unix socket. A daemon on `0.0.0.0` with no auth is an open door, and today
//! that is one config line away from the first: change a bind address, or put
//! the container on a shared network, and an unauthenticated store becomes
//! reachable by anything that can route to it. Nothing in the code stops that
//! today, and nothing warns.
//!
//! So the daemon refuses to boot into that shape. Not a lint, not a review
//! item — the process will not start.
//!
//! ## Why the escape hatch exists anyway
//!
//! `--insecure-no-auth` still allows it, because there *are* legitimate
//! wide-open deployments: a docker-compose E2E on a container network, a
//! throwaway cluster in CI. Those are already wide open — the flag does not
//! make them worse. What it does is make the openness **something the
//! deployment says out loud**, once, in a place a reader can grep for.
//!
//! ## What this deliberately does NOT do
//!
//! It does not narrow `DEFAULT_BIND`. `0.0.0.0` is not the hazard — plenty of
//! deployments need it, federation above all. The hazard is the *combination*
//! of a reachable bind with no way to tell callers apart. So the combination
//! is what becomes illegal, and the default keeps working for everyone who
//! authenticates.

use anyhow::{bail, Result};
use std::net::{IpAddr, SocketAddr};

/// How this daemon will treat an incoming caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPosture {
    /// Resolve `sk-` credentials against the replicated key store, using this
    /// HMAC signing secret.
    ApiKey(String),
    /// Authenticate nobody: every caller, including one presenting no token at
    /// all, is a system admin. Legal only where [`is_loopback_bind`] holds, or
    /// where the operator said `--insecure-no-auth` out loud.
    Open,
}

/// Everything the decision reads. Kept as a plain struct so the rule is a pure
/// function — testable without a daemon, and impossible to accidentally couple
/// to boot order.
#[derive(Debug, Clone)]
pub struct AuthPostureInputs {
    /// `--bind-addr` as given. Parsed here; an unparseable value is treated as
    /// non-loopback (fail closed — we cannot prove it is safe).
    pub bind_addr: String,
    /// `NEXUS_API_KEY_SECRET`. `None` or empty ⇒ no credential policy.
    pub api_key_secret: Option<String>,
    /// mTLS is enforced (i.e. `--no-tls` was NOT passed). A verified client
    /// certificate is itself an authentication, so a TLS daemon on a reachable
    /// address is not an open door.
    pub tls_enabled: bool,
    /// The operator explicitly accepts serving an unauthenticated, reachable
    /// socket.
    pub insecure_no_auth: bool,
}

/// Does `bind_addr` reach only this host?
///
/// An unparseable address is reported as **not** loopback. We are deciding
/// whether it is safe to authenticate nobody; "I could not tell" has to mean
/// "no".
pub fn is_loopback_bind(bind_addr: &str) -> bool {
    // The common form: `host:port`.
    if let Ok(sock) = bind_addr.parse::<SocketAddr>() {
        return sock.ip().is_loopback();
    }
    // A bare address with no port.
    if let Ok(ip) = bind_addr.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    // `localhost:2126` and friends — the hostname never reaches the resolver
    // here, so match the two spellings that unambiguously mean this host.
    let host = bind_addr.rsplit_once(':').map_or(bind_addr, |(h, _)| h);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    matches!(host, "localhost" | "localhost.")
}

/// Apply the invariant.
pub fn decide(inputs: &AuthPostureInputs) -> Result<AuthPosture> {
    let secret = inputs
        .api_key_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // A credential policy answers the question, wherever we are bound.
    if let Some(secret) = secret {
        return Ok(AuthPosture::ApiKey(secret));
    }

    // No credential policy. Serving nobody-in-particular is legal only where a
    // caller had to already be on this host.
    if is_loopback_bind(&inputs.bind_addr) {
        tracing::warn!(
            bind = %inputs.bind_addr,
            "serving WITHOUT authentication — every caller, including one with no \
             token, is a system admin on this node's VFS. Legal here only because \
             the bind is loopback. Set NEXUS_API_KEY_SECRET to authenticate callers."
        );
        return Ok(AuthPosture::Open);
    }

    // Reachable bind. A verified client certificate is an authentication, so
    // mTLS carries the daemon on its own.
    if inputs.tls_enabled {
        return Ok(AuthPosture::Open);
    }

    // Reachable, plaintext, and nobody is asked who they are.
    if inputs.insecure_no_auth {
        tracing::warn!(
            bind = %inputs.bind_addr,
            "SERVING AN UNAUTHENTICATED SOCKET ON A REACHABLE ADDRESS \
             (--insecure-no-auth). Anything that can route to this address is a \
             system admin on this node's VFS."
        );
        return Ok(AuthPosture::Open);
    }

    bail!(
        "refusing to start: this daemon would serve an UNAUTHENTICATED gRPC socket on \
         {bind}, which is not loopback.\n\n\
         Anything that can route to that address would be a system admin on this node's \
         VFS — no token required. Pick one:\n\n\
         \x20 · authenticate callers — set NEXUS_API_KEY_SECRET and mint keys with \
         `nexusd-cluster auth mint` (recommended);\n\
         \x20 · authenticate peers — drop --no-tls so mTLS verifies client certificates;\n\
         \x20 · bind to loopback — --bind-addr 127.0.0.1:<port>, if the only callers are \
         on this host;\n\
         \x20 · accept the exposure — pass --insecure-no-auth (or \
         NEXUS_INSECURE_NO_AUTH=1). Appropriate for a CI / docker-compose cluster that \
         is already wide open; never for anything holding real data.",
        bind = inputs.bind_addr
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(bind: &str) -> AuthPostureInputs {
        AuthPostureInputs {
            bind_addr: bind.to_string(),
            api_key_secret: None,
            tls_enabled: false,
            insecure_no_auth: false,
        }
    }

    // ── The shape moss actually runs ─────────────────────────────────

    /// The deployment this invariant must not break: a plaintext, tokenless
    /// daemon on loopback, spawned as a child of the process that talks to it.
    /// That is a trusted local backend, and it stays legal with no flags.
    #[test]
    fn loopback_without_auth_is_legal_and_needs_no_flag() {
        assert_eq!(
            decide(&inputs("127.0.0.1:2126")).unwrap(),
            AuthPosture::Open
        );
        assert_eq!(decide(&inputs("[::1]:2126")).unwrap(), AuthPosture::Open);
        assert_eq!(
            decide(&inputs("localhost:2126")).unwrap(),
            AuthPosture::Open
        );
    }

    // ── The shape that is one config line away ───────────────────────

    /// The whole point. Change the bind and the daemon stops, rather than
    /// silently becoming an unauthenticated store on a shared network.
    #[test]
    fn a_reachable_bind_without_auth_refuses_to_start() {
        for bind in [
            "0.0.0.0:2126",
            "10.0.0.4:2126",
            "[::]:2126",
            "192.168.1.7:2126",
        ] {
            let err = decide(&inputs(bind)).expect_err(&format!("{bind} must refuse"));
            let msg = err.to_string();
            assert!(msg.contains("refusing to start"), "{bind}: {msg}");
            // The error has to say what to do, not just that it is unhappy.
            assert!(
                msg.contains("NEXUS_API_KEY_SECRET"),
                "{bind}: no remedy offered"
            );
            assert!(
                msg.contains("--insecure-no-auth"),
                "{bind}: no escape offered"
            );
        }
    }

    /// An address we cannot parse is not one we can prove is safe.
    #[test]
    fn an_unparseable_bind_is_treated_as_reachable() {
        assert!(!is_loopback_bind("not-an-address"));
        assert!(decide(&inputs("not-an-address")).is_err());
    }

    /// `127.x` is all loopback, not just `127.0.0.1`.
    #[test]
    fn the_whole_loopback_range_counts() {
        assert!(is_loopback_bind("127.0.0.1:2126"));
        assert!(is_loopback_bind("127.1.2.3:2126"));
        assert!(is_loopback_bind("[::1]:2126"));
        assert!(!is_loopback_bind("0.0.0.0:2126"));
        assert!(!is_loopback_bind("128.0.0.1:2126"));
    }

    // ── The three ways to be legal on a reachable address ─────────────

    #[test]
    fn a_credential_policy_authenticates_anywhere() {
        let mut i = inputs("0.0.0.0:2126");
        i.api_key_secret = Some("s3cret".into());
        assert_eq!(decide(&i).unwrap(), AuthPosture::ApiKey("s3cret".into()));
    }

    /// An empty secret is not a secret. It must not be mistaken for one — that
    /// would put every install in a single key space.
    #[test]
    fn an_empty_secret_does_not_count_as_a_policy() {
        let mut i = inputs("0.0.0.0:2126");
        i.api_key_secret = Some(String::new());
        assert!(
            decide(&i).is_err(),
            "an empty secret must not authenticate anyone"
        );
    }

    /// mTLS verifies the client certificate, so the caller is already
    /// authenticated by the time a handler runs. Federation rides this.
    #[test]
    fn mtls_carries_a_reachable_bind_on_its_own() {
        let mut i = inputs("0.0.0.0:2126");
        i.tls_enabled = true;
        assert_eq!(decide(&i).unwrap(), AuthPosture::Open);
    }

    /// The escape hatch. Existing wide-open CI / docker clusters keep working —
    /// but only by saying so.
    #[test]
    fn insecure_no_auth_is_the_only_way_to_be_wide_open_and_reachable() {
        let mut i = inputs("0.0.0.0:2126");
        assert!(decide(&i).is_err(), "must refuse without the flag");
        i.insecure_no_auth = true;
        assert_eq!(decide(&i).unwrap(), AuthPosture::Open);
    }

    /// The flag is about the *reachable + plaintext* case. On loopback it is
    /// simply unnecessary — no one should have to pass it to run a local daemon.
    #[test]
    fn the_flag_is_not_needed_on_loopback() {
        let i = inputs("127.0.0.1:2126");
        assert!(!i.insecure_no_auth);
        assert!(decide(&i).is_ok());
    }

    /// A credential policy wins over the escape hatch: if a secret is set, the
    /// daemon authenticates, flag or no flag.
    #[test]
    fn a_secret_beats_the_escape_hatch() {
        let mut i = inputs("0.0.0.0:2126");
        i.api_key_secret = Some("s3cret".into());
        i.insecure_no_auth = true;
        assert_eq!(decide(&i).unwrap(), AuthPosture::ApiKey("s3cret".into()));
    }
}
