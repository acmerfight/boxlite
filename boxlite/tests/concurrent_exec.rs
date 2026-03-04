//! Integration tests for concurrent exec() calls.
//!
//! Verifies that multiple exec() calls can run concurrently on a single box.
//! Bug: ≥4 concurrent exec() calls cause permanent deadlock.
//!
//! Requires a real VM runtime (alpine:latest image).
//! Run with:
//!
//! ```sh
//! cargo test -p boxlite --test concurrent_exec
//! ```

mod common;

use boxlite::BoxCommand;
use boxlite::BoxliteRuntime;
use boxlite::runtime::options::BoxliteOptions;
use std::time::Duration;
use tokio_stream::StreamExt;

/// Exec a short command, collect stdout, return (exit_code, stdout).
async fn exec_echo(handle: &boxlite::LiteBox, msg: String) -> (i32, String) {
    let mut execution = handle
        .exec(BoxCommand::new("echo").arg(&msg))
        .await
        .expect("exec() failed");

    let mut stdout = String::new();
    if let Some(mut stream) = execution.stdout() {
        while let Some(chunk) = stream.next().await {
            stdout.push_str(&chunk);
        }
    }

    let result = execution.wait().await.expect("wait() failed");
    (result.exit_code, stdout)
}

// ============================================================================
// CONCURRENT EXEC TESTS
// ============================================================================

/// Baseline: 3 concurrent exec() calls should succeed.
///
/// This matches the observed threshold where things still work.
#[tokio::test]
async fn concurrent_exec_3_succeeds() {
    let home = boxlite_test_utils::home::PerTestBoxHome::new();
    let runtime = BoxliteRuntime::new(BoxliteOptions {
        home_dir: home.path.clone(),
        image_registries: common::test_registries(),
    })
    .expect("create runtime");
    let handle = runtime
        .create(common::alpine_opts_auto(), None)
        .await
        .unwrap();
    handle.start().await.unwrap();

    let n = 3;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let futs: Vec<_> = (0..n)
            .map(|i| exec_echo(&handle, format!("hello-{}", i)))
            .collect();
        futures::future::join_all(futs).await
    })
    .await;

    let results = result.expect("3 concurrent exec() calls should not deadlock");

    for (i, (exit_code, stdout)) in results.iter().enumerate() {
        assert_eq!(*exit_code, 0, "exec {i} should exit 0");
        assert!(
            stdout.contains(&format!("hello-{i}")),
            "exec {i} stdout should contain 'hello-{i}', got: {stdout:?}"
        );
    }

    let _ = runtime.shutdown(Some(common::TEST_SHUTDOWN_TIMEOUT)).await;
}

/// Bug reproduction: 4 concurrent exec() calls deadlock.
///
/// Each exec() spawns 3 long-lived gRPC streams (send_input, attach, wait),
/// all multiplexed over a single tonic Channel. At N=4 (12 concurrent streams),
/// the system deadlocks permanently.
///
/// This test uses a 30-second timeout to detect the deadlock.
#[tokio::test]
async fn concurrent_exec_4_should_not_deadlock() {
    let home = boxlite_test_utils::home::PerTestBoxHome::new();
    let runtime = BoxliteRuntime::new(BoxliteOptions {
        home_dir: home.path.clone(),
        image_registries: common::test_registries(),
    })
    .expect("create runtime");
    let handle = runtime
        .create(common::alpine_opts_auto(), None)
        .await
        .unwrap();
    handle.start().await.unwrap();

    let n = 4;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let futs: Vec<_> = (0..n)
            .map(|i| exec_echo(&handle, format!("hello-{}", i)))
            .collect();
        futures::future::join_all(futs).await
    })
    .await;

    assert!(
        result.is_ok(),
        "4 concurrent exec() calls deadlocked (timed out after 30s)"
    );

    let results = result.unwrap();
    for (i, (exit_code, stdout)) in results.iter().enumerate() {
        assert_eq!(*exit_code, 0, "exec {i} should exit 0");
        assert!(
            stdout.contains(&format!("hello-{i}")),
            "exec {i} stdout should contain 'hello-{i}', got: {stdout:?}"
        );
    }

    let _ = runtime.shutdown(Some(common::TEST_SHUTDOWN_TIMEOUT)).await;
}

/// Extended test: 8 concurrent exec() calls.
///
/// If the N=4 deadlock is fixed, this verifies the fix scales beyond
/// the original threshold.
#[tokio::test]
async fn concurrent_exec_8_should_not_deadlock() {
    let home = boxlite_test_utils::home::PerTestBoxHome::new();
    let runtime = BoxliteRuntime::new(BoxliteOptions {
        home_dir: home.path.clone(),
        image_registries: common::test_registries(),
    })
    .expect("create runtime");
    let handle = runtime
        .create(common::alpine_opts_auto(), None)
        .await
        .unwrap();
    handle.start().await.unwrap();

    let n = 8;
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        let futs: Vec<_> = (0..n)
            .map(|i| exec_echo(&handle, format!("hello-{}", i)))
            .collect();
        futures::future::join_all(futs).await
    })
    .await;

    assert!(
        result.is_ok(),
        "8 concurrent exec() calls deadlocked (timed out after 60s)"
    );

    let results = result.unwrap();
    for (i, (exit_code, stdout)) in results.iter().enumerate() {
        assert_eq!(*exit_code, 0, "exec {i} should exit 0");
        assert!(
            stdout.contains(&format!("hello-{i}")),
            "exec {i} stdout should contain 'hello-{i}', got: {stdout:?}"
        );
    }

    let _ = runtime.shutdown(Some(common::TEST_SHUTDOWN_TIMEOUT)).await;
}
