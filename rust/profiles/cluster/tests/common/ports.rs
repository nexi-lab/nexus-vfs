//! Shared port allocation for daemon and in-process transport tests.

#![allow(dead_code)]

/// Ports are handed out from this band, which sits BELOW every platform's ephemeral
/// range (Linux 32768+, macOS/Windows 49152+).
///
/// That is the whole point. A harness port is not used by the process that picks it —
/// it is handed to a daemon that binds it moments later — so binding `:0` and
/// releasing it asks the OS for a number and then hopes nobody takes it. The OS hands
/// out ephemeral ports freely in that window, including to the next test doing the
/// same thing, and a daemon that loses the race exits with `Address already in use`
/// and is reported as whatever the test was actually asserting.
///
/// Out here the OS assigns nothing spontaneously, so the only competitors are our own
/// handouts — which the counter below makes disjoint.
const PORT_BAND_START: u16 = 20_000;
const PORT_BAND_END: u16 = 32_000;

/// Next candidate in the band, started at a pid-derived offset.
///
/// The counter separates handouts within one test binary; the pid seed separates
/// concurrent binaries, which otherwise start at the same place and collide in step.
/// Same reasoning as temp-dir naming: a counter is disjoint by construction where a
/// clock or a random draw is disjoint by luck.
static PORT_CURSOR: std::sync::LazyLock<std::sync::atomic::AtomicU32> =
    std::sync::LazyLock::new(|| {
        let span = u32::from(PORT_BAND_END - PORT_BAND_START);
        std::sync::atomic::AtomicU32::new(std::process::id().wrapping_mul(37) % span)
    });

/// Reserve `count` CONSECUTIVE ports in the band and return the first.
///
/// One `fetch_add` claims the whole run, which is what makes a multi-port reservation
/// safe under parallel tests: claiming ports one at a time lets two callers interleave
/// and both believe they own `p + 1`, since a probe only proves nobody has BOUND it
/// yet — not that nobody else has been handed the number.
///
/// Each port in the run is still probed, so an unrelated service inside the band is
/// skipped rather than inherited.
fn reserve_ports(count: u32) -> u16 {
    let span = u32::from(PORT_BAND_END - PORT_BAND_START);
    for _ in 0..span {
        let start = PORT_CURSOR.fetch_add(count, std::sync::atomic::Ordering::Relaxed) % span;
        // A run that would straddle the band's end is skipped rather than wrapped, so
        // "consecutive" stays true.
        if start + count > span {
            continue;
        }
        let base = PORT_BAND_START + start as u16;
        if (0..count).all(|i| std::net::TcpListener::bind(("127.0.0.1", base + i as u16)).is_ok()) {
            return base;
        }
    }
    panic!("no free {count}-port run in {PORT_BAND_START}..{PORT_BAND_END} — is something holding the band?");
}

/// A port to hand to a daemon this test is about to spawn.
pub fn free_port() -> u16 {
    reserve_ports(1)
}

/// A data-plane port `p` such that `p + 1` is ALSO free — for the enrollment
/// convention (the node-enrollment listener rides one port above the data plane; both
/// sides derive `p + 1`). Returns `p`, with the neighbour reserved so no other caller
/// is handed it.
pub fn free_port_pair() -> u16 {
    reserve_ports(2)
}

#[cfg(test)]
mod port_allocation_tests {
    use super::{free_port, free_port_pair, PORT_BAND_END, PORT_BAND_START};

    /// Handouts are disjoint and inside the band.
    ///
    /// The property the band exists for: two daemons must never be handed the same
    /// port. Asserted directly because the old `:0` form could only be observed
    /// failing — as a daemon exiting with `Address already in use`, attributed to
    /// whatever test happened to lose the race.
    #[test]
    fn every_handout_is_distinct_and_in_band() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let p = free_port();
            assert!(
                (PORT_BAND_START..PORT_BAND_END).contains(&p),
                "port {p} is outside the band"
            );
            assert!(seen.insert(p), "port {p} was handed out twice");
        }
    }

    /// A pair takes its neighbour out of circulation.
    ///
    /// `p + 1` belongs to this caller's enrollment listener, so no later handout may
    /// be it — the reason the pair is reserved in one `fetch_add` rather than probed.
    #[test]
    fn a_pair_reserves_its_neighbour() {
        let pairs: Vec<u16> = (0..8).map(|_| free_port_pair()).collect();
        let mut later = std::collections::BTreeSet::new();
        for _ in 0..32 {
            later.insert(free_port());
        }
        for p in pairs {
            assert!(
                p + 1 < PORT_BAND_END,
                "pair {p} has no room for its neighbour"
            );
            assert!(
                !later.contains(&p) && !later.contains(&(p + 1)),
                "a later handout collided with the pair ({p}, {})",
                p + 1
            );
        }
    }
}
