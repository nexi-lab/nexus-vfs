//! The same real-process journey runs under Cargo and against the optimized
//! Windows CI artifacts. Keep its RPC/recovery assertions in one place.
#![cfg(feature = "operator-agent-enrollment")]

#[test]
fn operator_enrollment_reuses_the_live_minter_and_never_replays_unknown() {
    let output = tempfile::tempdir().unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/e2e/operator_agent_enrollment.py");
    let python = std::env::var_os("NEXUS_TEST_PYTHON")
        .unwrap_or_else(|| if cfg!(windows) { "python" } else { "python3" }.into());
    let result = std::process::Command::new(python)
        .arg(script)
        .args(["--daemon", env!("CARGO_BIN_EXE_nexusd-cluster")])
        .args(["--operator", env!("CARGO_BIN_EXE_nexus-agent-enroll")])
        .arg("--output")
        .arg(output.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "operator journey failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
}
