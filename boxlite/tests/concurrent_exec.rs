//! Integration tests for concurrent exec() on a single box.
//!
//! Validates that multiple exec() calls can be issued concurrently
//! (via join_all), matching the documented usage pattern:
//!
//! ```python
//! results = await asyncio.gather(
//!     box.exec("echo", ["task A"]),
//!     box.exec("echo", ["task B"]),
//! )
//! ```
//!
//! # Prerequisites
//!
//! 1. Build the runtime: `make runtime-debug`
//! 2. Run with: `cargo test -p boxlite --test concurrent_exec -- --nocapture`

mod common;

use boxlite::BoxCommand;
use boxlite::BoxliteRuntime;
use boxlite::runtime::options::BoxliteOptions;
use std::time::Duration;

/// Concurrent exec() calls on the same box must not deadlock.
#[tokio::test]
async fn concurrent_exec_should_not_deadlock() {
    const N: usize = 4;

    let home = boxlite_test_utils::home::PerTestBoxHome::new();
    let runtime = BoxliteRuntime::new(BoxliteOptions {
        home_dir: home.path.clone(),
        image_registries: common::test_registries(),
    })
    .expect("create runtime");
    let handle = runtime.create(common::alpine_opts(), None).await.unwrap();
    handle.start().await.unwrap();

    let exec_futures: Vec<_> = (0..N)
        .map(|i| {
            let h = &handle;
            async move {
                let exec_result = h
                    .exec(BoxCommand::new("echo").arg(format!("hello-{}", i)))
                    .await;

                match exec_result {
                    Ok(mut execution) => {
                        let wait_result = execution.wait().await;
                        (i, Ok(wait_result))
                    }
                    Err(e) => (i, Err(e)),
                }
            }
        })
        .collect();

    let results = tokio::time::timeout(
        Duration::from_secs(30),
        futures::future::join_all(exec_futures),
    )
    .await
    .expect("DEADLOCK: concurrent exec() did not complete within 30s");

    println!("=== concurrent_exec_should_not_deadlock (N={}) ===", N);

    let mut success = 0;
    for (i, result) in &results {
        match result {
            Ok(Ok(r)) => {
                println!("  exec[{}]: exit_code={}", i, r.exit_code);
                assert_eq!(r.exit_code, 0, "exec[{}] should succeed", i);
                success += 1;
            }
            Ok(Err(e)) => println!("  exec[{}]: wait error: {}", i, e),
            Err(e) => println!("  exec[{}]: exec error: {}", i, e),
        }
    }

    assert_eq!(success, N, "All {} concurrent execs must succeed", N);

    let _ = runtime.remove(handle.id().as_str(), true).await;
    let _ = runtime.shutdown(Some(common::TEST_SHUTDOWN_TIMEOUT)).await;
}
