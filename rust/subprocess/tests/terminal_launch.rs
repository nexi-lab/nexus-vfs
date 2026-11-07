//! Real terminal -> local launcher -> inherited-terminal child. The ignored
//! entries are subprocess fixtures, invoked only by the parent PTY tests.

use std::collections::HashMap;
use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use pty_expect::PtySession;
use subprocess::terminal::{
    connect_bootstrap, PreparedTerminalLaunch, TerminalLauncher, BOOTSTRAP_ENV,
};
use subprocess::HostedSubprocess;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture_argv(name: &str) -> Vec<String> {
    vec![
        std::env::current_exe().unwrap().display().to_string(),
        "--exact".into(),
        name.into(),
        "--ignored".into(),
        "--nocapture".into(),
    ]
}

fn terminal(name: &str) -> PtySession {
    let argv = fixture_argv(name);
    let args: Vec<_> = argv[1..].iter().map(String::as_str).collect();
    let mut session = PtySession::spawn(&argv[0], &args).unwrap();
    session.set_default_timeout(Duration::from_secs(15));
    session
}

#[test]
fn inherited_terminal_keeps_input_controlling_tty_and_exit_status() {
    let mut session = terminal("launcher_fixture");
    session.expect("TERMINAL_CHILD_READY").unwrap();
    session.send("native-input-123\r").unwrap();
    session.expect("CHILD_RECEIVED:native-input-123").unwrap();
    session.expect("CHILD_REAPED:17").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
fn launcher_cancels_and_reaps_its_actual_child() {
    let mut session = terminal("cancel_fixture");
    session.expect("CANCELLED_CHILD_REAPED").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
fn admitted_launcher_keeps_terminal_bytes_out_of_the_control_channel() {
    let mut session = terminal("admitted_launcher_fixture");
    session.expect("ADMITTED_TERMINAL_READY").unwrap();
    session.send("visible-terminal-input\r").unwrap();
    session
        .expect("VISIBLE_CHILD_REPLY:visible-terminal-input")
        .unwrap();
    session.expect("ADMITTED_CHILD_REAPED").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
fn revoked_control_connection_stops_and_reaps_the_terminal_child() {
    let mut session = terminal("revoked_launcher_fixture");
    session
        .expect("REVOKED_CHILD_REAPED")
        .unwrap_or_else(|error| {
            panic!(
                "{error}; terminal: {}",
                session.render(|screen| screen.contents())
            )
        });
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
fn admission_failure_reaps_a_child_that_has_not_connected_its_runtime() {
    let mut session = terminal("revoked_bootstrap_fixture");
    session.expect("BOOTSTRAP_CHILD_REAPED").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
#[ignore = "real PTY fixture for admission failure after OS child creation"]
fn revoked_bootstrap_fixture() {
    let marker = std::env::temp_dir().join(format!("terminal-boot-stall-{}", uuid::Uuid::new_v4()));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let launcher = TerminalLauncher::bind().await.unwrap();
            let offer = launcher.offer().clone();
            let (cancel, cancelled) = tokio::sync::oneshot::channel();
            let manager = async {
                let prepared = PreparedTerminalLaunch::connect(&offer).await.unwrap();
                let _stream = prepared
                    .start(&serde_json::json!({"fixture":"bootstrap-failure"}))
                    .await
                    .unwrap();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                while !marker.exists() {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "child never reached its real entrypoint"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                cancel.send(()).unwrap();
            };
            let mut environment: HashMap<String, String> = std::env::vars().collect();
            environment.insert("BOOT_STALL_MARKER".into(), marker.display().to_string());
            let run = launcher.run_with_shutdown(
                fixture_argv("stalled_runtime_fixture"),
                environment,
                std::path::Path::new("."),
                async {
                    cancelled.await.unwrap();
                },
            );
            let (exit, ()) = tokio::join!(run, manager);
            assert_eq!(exit.unwrap_err().kind(), io::ErrorKind::Interrupted);
        });
    #[cfg(unix)]
    {
        let pid: libc::pid_t = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
        let mut status = 0;
        // This exact child was spawned by this fixture, so ECHILD proves the
        // launcher already reaped it; a live child would return zero instead.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    std::fs::remove_file(marker).unwrap();
    println!("BOOTSTRAP_CHILD_REAPED");
}

#[test]
#[ignore = "child stalls before connecting its managed runtime"]
fn stalled_runtime_fixture() {
    let marker = std::env::var("BOOT_STALL_MARKER").unwrap();
    std::fs::write(marker, std::process::id().to_string()).unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    panic!("bootstrap-stalled child must be cancelled before terminal input");
}

fn admitted_launcher(revoke: bool) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let launcher = TerminalLauncher::bind().await.unwrap();
            let offer = launcher.offer().clone();
            let grant = serde_json::json!({"session_id":"fixture-managed-instance"});
            let manager = async move {
                let prepared = PreparedTerminalLaunch::connect(&offer).await.unwrap();
                let mut stream = prepared.start(&grant).await.unwrap();
                let mut readiness = [0; 14];
                stream.read_exact(&mut readiness).await.unwrap();
                assert_eq!(&readiness, b"CONTROL_READY\n");
                if revoke {
                    println!("REVOKE_RUNTIME_READY");
                }
                // Readiness proves the first admission has consumed and closed
                // its listener. Racing a second TCP connect against accept's
                // return can enter the OS backlog and spend the full handshake
                // timeout before the separate child shutdown grace even begins.
                assert!(
                    PreparedTerminalLaunch::connect(&offer).await.is_err(),
                    "a terminal launch capability must be consumed exactly once"
                );
                if revoke {
                    println!("REVOKE_CAPABILITY_CONSUMED");
                    drop(stream);
                    println!("REVOKE_MANAGER_DROPPED");
                    return;
                }
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                let receipt: serde_json::Value = serde_json::from_slice(&received).unwrap();
                assert_eq!(
                    receipt["method"],
                    contracts::local_launch::TERMINAL_EXIT_METHOD
                );
                assert_eq!(receipt["params"]["code"], 17);
                assert!(receipt["params"]["signal"].is_null());
                assert!(
                    !String::from_utf8_lossy(&received).contains("VISIBLE_CHILD_REPLY"),
                    "native terminal output leaked into the control channel"
                );
            };
            let run = launcher.run(
                fixture_argv("admitted_guest_fixture"),
                std::env::vars().collect(),
                std::path::Path::new("."),
            );
            let (exit, ()) = tokio::join!(run, manager);
            let exit = exit.unwrap();
            if revoke {
                assert_ne!(exit.code, Some(0));
                assert_ne!(exit.code, Some(17));
                assert!(exit.code.is_some() || exit.signal.is_some());
                println!("REVOKED_CHILD_REAPED");
            } else {
                assert_eq!(exit.code, Some(17));
                println!("ADMITTED_CHILD_REAPED");
            }
        });
}

#[test]
#[ignore = "invoked in a real PTY by admitted_launcher_keeps_terminal_bytes_out_of_the_control_channel"]
fn admitted_launcher_fixture() {
    admitted_launcher(false);
}

#[test]
#[ignore = "invoked in a real PTY by revoked_control_connection_stops_and_reaps_the_terminal_child"]
fn revoked_launcher_fixture() {
    admitted_launcher(true);
}

#[test]
#[ignore = "native runtime fixture launched through the one-use bootstrap"]
fn admitted_guest_fixture() {
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (_stream, grant) = executor.block_on(async {
        let offer = serde_json::from_str(&std::env::var(BOOTSTRAP_ENV).unwrap()).unwrap();
        let (mut stream, grant) = connect_bootstrap(offer).await.unwrap();
        stream.write_all(b"CONTROL_READY\n").await.unwrap();
        (stream, grant)
    });
    assert_eq!(grant["session_id"], "fixture-managed-instance");
    assert!(io::stdin().is_terminal());
    assert!(io::stdout().is_terminal());
    println!("ADMITTED_TERMINAL_READY");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    println!("VISIBLE_CHILD_REPLY:{}", line.trim_end());
    io::stdout().flush().unwrap();
    std::process::exit(17);
}

async fn spawn_guest() -> HostedSubprocess {
    let environment: HashMap<_, _> = std::env::vars().collect();
    #[cfg(unix)]
    let environment = {
        let mut environment = environment;
        // These read-only OS calls let the child verify the original session
        // and foreground process group, not merely `isatty(stdin)`.
        environment.insert(
            "TEST_LAUNCHER_SID".into(),
            unsafe { libc::getsid(0) }.to_string(),
        );
        environment.insert(
            "TEST_LAUNCHER_PGRP".into(),
            unsafe { libc::getpgrp() }.to_string(),
        );
        environment
    };
    let mut child = HostedSubprocess::spawn_in_terminal(
        fixture_argv("terminal_guest_fixture"),
        environment,
        &std::env::current_dir().unwrap(),
    )
    .await
    .unwrap();
    assert!(child.os_pid().is_some());
    assert!(
        child.take_stdio_for_connection().is_err(),
        "terminal bytes must not be piped"
    );
    child
}

#[test]
#[ignore = "invoked in a real PTY by inherited_terminal_keeps_input_controlling_tty_and_exit_status"]
fn launcher_fixture() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut child = spawn_guest().await;
            let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .unwrap();
            assert_eq!(status.code, Some(17));
            assert_eq!(status.signal, None);
            assert!(child.os_pid().is_none(), "wait must reap the owned child");
            println!("CHILD_REAPED:17");
        });
}

#[test]
#[ignore = "invoked in a real PTY by launcher_cancels_and_reaps_its_actual_child"]
fn cancel_fixture() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut child = spawn_guest().await;
            child.kill().await;
            let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .unwrap();
            assert_ne!(status.code, Some(0));
            assert!(status.code.is_some() || status.signal.is_some());
            assert!(child.os_pid().is_none());
            println!("CANCELLED_CHILD_REAPED");
        });
}

#[test]
#[ignore = "child fixture launched by the terminal's local launcher"]
fn terminal_guest_fixture() {
    assert!(io::stdin().is_terminal());
    assert!(io::stdout().is_terminal());
    assert!(io::stderr().is_terminal());
    #[cfg(unix)]
    {
        let _controlling_tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .unwrap();
        let session: i32 = std::env::var("TEST_LAUNCHER_SID").unwrap().parse().unwrap();
        let group: i32 = std::env::var("TEST_LAUNCHER_PGRP")
            .unwrap()
            .parse()
            .unwrap();
        // Read-only process/terminal queries; fd 0 is the inherited PTY slave.
        assert_eq!(unsafe { libc::getsid(0) }, session);
        assert_eq!(unsafe { libc::getpgrp() }, group);
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, group);
    }
    println!("TERMINAL_CHILD_READY");
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    println!("CHILD_RECEIVED:{}", line.trim_end());
    io::stdout().flush().unwrap();
    std::process::exit(17);
}
