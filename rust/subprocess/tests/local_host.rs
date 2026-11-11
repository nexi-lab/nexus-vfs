//! Real PTY/ConPTY journeys through the one-use same-process host connection.
//! Only the test parent owns an OS child; the product host starts no supervisor.

use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use pty_expect::PtySession;
use serde_json::json;
use subprocess::local_host::{LocalHost, PreparedLocalHost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn terminal(name: &str) -> PtySession {
    let executable = std::env::current_exe().unwrap();
    let mut session = PtySession::spawn(
        executable.to_str().unwrap(),
        &["--exact", name, "--ignored", "--nocapture"],
    )
    .unwrap();
    session.set_default_timeout(Duration::from_secs(15));
    session
}

#[test]
fn admission_keeps_the_same_process_and_controlling_terminal() {
    let mut session = terminal("native_host_fixture");
    session.expect("NATIVE_HOST_READY").unwrap();
    session.send("native-input-123\r").unwrap();
    session.expect("TERMINAL_REPLY:native-input-123").unwrap();
    session.expect("CONTROL_AND_TERMINAL_SEPARATE").unwrap();
    // The PTY parent, not a control-channel message, observes this OS exit.
    assert_eq!(session.expect_eof().unwrap(), 17);
}

#[test]
fn a_consumed_offer_cannot_admit_a_second_controller() {
    let mut session = terminal("consumed_offer_fixture");
    session.expect("OFFER_CONSUMED_ONCE").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
fn revoking_preparation_does_not_start_the_native_application() {
    let mut session = terminal("revoked_preparation_fixture");
    session.expect("PREPARATION_REVOKED").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 0);
}

#[test]
fn control_eof_is_not_an_os_process_exit_receipt() {
    let mut session = terminal("control_eof_fixture");
    session.expect("CONTROL_CLOSED_HOST_STILL_ALIVE").unwrap();
    // This read after EOF proves the actual terminal process is still alive.
    session.send("exit-from-terminal\r").unwrap();
    session.expect("TERMINAL_REPLY:exit-from-terminal").unwrap();
    assert_eq!(session.expect_eof().unwrap(), 17);
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn terminal_reply() {
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    println!("TERMINAL_REPLY:{}", line.trim_end());
    io::stdout().flush().unwrap();
}

fn check_terminal() {
    assert!(io::stdin().is_terminal());
    assert!(io::stdout().is_terminal());
    assert!(io::stderr().is_terminal());
    #[cfg(unix)]
    {
        let _tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .unwrap();
        // Read-only OS queries: admission must retain the foreground terminal.
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe { libc::getpgrp() });
    }
}

#[test]
#[ignore = "invoked by the real native-terminal PTY journey"]
fn native_host_fixture() {
    check_terminal();
    let pid = std::process::id();
    runtime().block_on(async {
        let host = LocalHost::bind().await.unwrap();
        let offer = host.offer().clone();
        let manager = async {
            let prepared = PreparedLocalHost::connect(&offer).await.unwrap();
            let mut stream = prepared
                .start(&json!({"session_id":"native-fixture"}))
                .await
                .unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"CONTROL_ONLY\n");
            println!("CONTROL_AND_TERMINAL_SEPARATE");
        };
        let native = async {
            let (mut stream, grant) = host.accept().await.unwrap();
            assert_eq!(grant["session_id"], "native-fixture");
            assert_eq!(std::process::id(), pid);
            check_terminal();
            println!("NATIVE_HOST_READY");
            io::stdout().flush().unwrap();
            tokio::task::spawn_blocking(terminal_reply).await.unwrap();
            stream.write_all(b"CONTROL_ONLY\n").await.unwrap();
        };
        tokio::join!(manager, native);
    });
    std::process::exit(17);
}

#[test]
#[ignore = "invoked by the one-use capability PTY journey"]
fn consumed_offer_fixture() {
    runtime().block_on(async {
        let host = LocalHost::bind().await.unwrap();
        let offer = host.offer().clone();
        let manager = async {
            // A wrong secret must not consume the valid local capability.
            let mut wrong = tokio::net::TcpStream::connect(offer.endpoint())
                .await
                .unwrap();
            wrong.write_all(&[b'x'; 32]).await.unwrap();
            let mut byte = [0];
            assert_eq!(wrong.read(&mut byte).await.unwrap(), 0);
            let prepared = PreparedLocalHost::connect(&offer).await.unwrap();
            let mut stream = prepared.start(&json!({"session_id":"once"})).await.unwrap();
            stream.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [1]);
            assert!(PreparedLocalHost::connect(&offer).await.is_err());
        };
        let native = async {
            let (mut stream, _) = host.accept().await.unwrap();
            // Acknowledgement occurs after accept consumed and closed the listener.
            stream.write_all(&[1]).await.unwrap();
        };
        tokio::join!(manager, native);
    });
    println!("OFFER_CONSUMED_ONCE");
}

#[test]
#[ignore = "invoked by the real preparation-revocation PTY journey"]
fn revoked_preparation_fixture() {
    runtime().block_on(async {
        let host = LocalHost::bind().await.unwrap();
        let offer = host.offer().clone();
        let manager = async {
            drop(PreparedLocalHost::connect(&offer).await.unwrap());
        };
        let ((), result) = tokio::join!(manager, host.accept());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    });
    println!("PREPARATION_REVOKED");
}

#[test]
#[ignore = "invoked by the control-EOF versus process-exit PTY journey"]
fn control_eof_fixture() {
    runtime().block_on(async {
        let host = LocalHost::bind().await.unwrap();
        let offer = host.offer().clone();
        let manager = async {
            let prepared = PreparedLocalHost::connect(&offer).await.unwrap();
            drop(prepared.start(&json!({"session_id":"eof"})).await.unwrap());
        };
        let native = async {
            let (mut stream, _) = host.accept().await.unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        };
        tokio::join!(manager, native);
    });
    check_terminal();
    println!("CONTROL_CLOSED_HOST_STILL_ALIVE");
    io::stdout().flush().unwrap();
    terminal_reply();
    std::process::exit(17);
}
