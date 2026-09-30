//! Shared harness bits for the raft integration tests.
//!
//! Only one thing so far, and it is here because fifteen test files each had
//! their own copy of the bug it fixes.

#![allow(dead_code)] // each test file uses a different subset

/// Ports are handed out from this band, which sits BELOW every platform's
/// ephemeral range (Linux 32768+, macOS/Windows 49152+).
///
/// That is the whole point. A harness port is not used by the process that
/// picks it — it is handed to a `ZoneManager` that binds it moments later — so
/// binding `:0` and releasing it asks the OS for a number and then hopes
/// nobody takes it. The OS hands out ephemeral ports freely in that window,
/// including to the next test binary doing the same thing, and the node that
/// loses the race dies with `Address already in use` during server startup.
/// The harness reports that as "test exited abnormally", which names neither
/// the port nor the winner.
///
/// Out here the OS assigns nothing spontaneously, so the only competitors are
/// our own handouts — which the counter below makes disjoint.
///
/// Deliberately a DIFFERENT band from the `nexus-cluster` harness's
/// 20000..32000: these suites run concurrently under a workspace-wide
/// `cargo test`, and two bands that overlap would reintroduce across suites
/// exactly the collision each one removes within itself.
const PORT_BAND_START: u16 = 15_000;
const PORT_BAND_END: u16 = 20_000;

/// Next candidate in the band, started at a pid-derived offset.
///
/// The counter separates handouts within one test binary; the pid seed
/// separates concurrent binaries, which otherwise start at the same place and
/// collide in step. A counter is disjoint by construction where a clock or a
/// random draw is disjoint by luck.
static PORT_CURSOR: std::sync::LazyLock<std::sync::atomic::AtomicU32> =
    std::sync::LazyLock::new(|| {
        let span = u32::from(PORT_BAND_END - PORT_BAND_START);
        std::sync::atomic::AtomicU32::new(std::process::id() % span)
    });

/// A `127.0.0.1:<port>` bind address for a node this test is about to start.
///
/// Returns the string rather than the number because that is what every
/// caller wanted: `ZoneManager` takes a bind address and an advertise URL
/// built from the same text, and handing back a `u16` only invited each test
/// to format it again.
pub fn node_bind_addr() -> String {
    node_bind_socket_addr().to_string()
}

/// The same handout as [`node_bind_addr`], typed — for the one caller that
/// hands a `SocketAddr` straight to a `ServerConfig`.
///
/// Two shapes over one allocator rather than two allocators: a second cursor
/// would hand out the same numbers as the first.
pub fn node_bind_socket_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], reserve_port()))
}

fn reserve_port() -> u16 {
    let span = u32::from(PORT_BAND_END - PORT_BAND_START);
    for _ in 0..span {
        let offset = PORT_CURSOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % span;
        let candidate = PORT_BAND_START + offset as u16;
        // Still probed, so an unrelated service inside the band is skipped
        // rather than inherited. The probe cannot prove the port stays free —
        // nothing can — but inside this band nobody is assigned it by the OS,
        // and the cursor means no other handout names it either.
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate;
        }
    }
    panic!("no free port in {PORT_BAND_START}..{PORT_BAND_END} — is something holding the band?");
}

/// Kept deliberately cheap: `mod common;` is compiled into all fifteen test
/// binaries, so everything here runs fifteen times. A self-test that claimed a
/// big slice of the band would compete with the very suites it exists to
/// protect.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Two handouts never name the same port. This is the property the old
    /// `bind(":0")` + `drop` could not offer, and the reason fifteen suites
    /// aborted at random under a workspace-wide test run.
    #[test]
    fn handouts_are_disjoint() {
        let seen: HashSet<String> = (0..32).map(|_| node_bind_addr()).collect();
        assert_eq!(seen.len(), 32, "a port was handed out twice");
    }

    /// And they stay out of the OS ephemeral range, which is what stops the
    /// OS handing the same number to something else mid-window.
    #[test]
    fn handouts_avoid_the_ephemeral_range() {
        for _ in 0..8 {
            let addr = node_bind_addr();
            let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
            assert!(
                (PORT_BAND_START..PORT_BAND_END).contains(&port),
                "{port} escaped the band"
            );
            assert!(port < 32_768, "{port} is inside Linux's ephemeral range");
        }
    }
}
