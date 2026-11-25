use super::ZoneManager;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

#[test]
fn cancelled_and_concurrent_shutdown_waiters_share_the_original_server_task() {
    let directory = tempfile::tempdir().unwrap();
    let manager = ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut shutdown = manager
        .shutdown_tx
        .blocking_lock()
        .as_ref()
        .unwrap()
        .subscribe();
    let (release, released) = tokio::sync::oneshot::channel();
    let (stopping, stopped_rx) = mpsc::channel();
    let server_finished = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&server_finished);
    // Hold a real listener after the original shutdown signal, as an
    // in-flight server request can hold graceful termination open.
    let server = manager.rt().spawn(async move {
        shutdown.changed().await.unwrap();
        stopping.send(()).unwrap();
        let _ = released.await;
        drop(listener);
        finished.store(true, Ordering::Release);
    });
    assert!(manager
        .server_task
        .blocking_lock()
        .replace(server)
        .is_none());

    let waiting_manager = Arc::clone(&manager);
    let waiting = manager
        .rt()
        .spawn(async move { waiting_manager.shutdown_async().await });
    stopped_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    waiting.abort();
    assert!(manager.rt().block_on(waiting).unwrap_err().is_cancelled());

    let first_manager = Arc::clone(&manager);
    let first = std::thread::spawn(move || first_manager.shutdown());

    let occupied = std::net::TcpListener::bind(address).err().unwrap().kind();

    let (entered, entered_rx) = mpsc::channel();
    let (done, done_rx) = mpsc::channel();
    let second_manager = Arc::clone(&manager);
    let second = std::thread::spawn(move || {
        entered.send(()).unwrap();
        second_manager.shutdown();
        done.send(server_finished.load(Ordering::Acquire)).unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let early = done_rx.recv_timeout(Duration::from_millis(100));
    // Release and join before checking the oracle, including the old-code
    // counterexample, so a failed assertion cannot strand the server task.
    release.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(occupied, std::io::ErrorKind::AddrInUse);
    let (returned_early, observed_server_finished) = match early {
        Ok(finished) => (true, finished),
        Err(mpsc::RecvTimeoutError::Timeout) => (false, done_rx.recv().unwrap()),
        Err(error) => panic!("shutdown worker disconnected: {error}"),
    };
    assert!(
        !returned_early && observed_server_finished,
        "every shutdown caller must wait for the original server task"
    );
    let rebound = std::net::TcpListener::bind(address).unwrap();
    drop(rebound);
    // A later call observes the same completed shutdown while the manager lives.
    manager.shutdown();
}
