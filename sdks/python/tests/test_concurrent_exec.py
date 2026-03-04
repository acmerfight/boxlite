"""
Integration tests for concurrent exec() calls.

Verifies that multiple exec() calls can run concurrently on a single box.
Bug: concurrent exec() calls cause permanent deadlock.

Root cause: Each exec() spawns 3 long-lived gRPC streaming tasks (send_input,
attach, wait) over a single tonic Channel. At N>=2 concurrent exec() calls
(6+ concurrent gRPC streams), the system deadlocks permanently through the
async API.

The threshold differs by API:
- Async Python API: N>=2 deadlocks (6 concurrent streams)
- Sync Python API (greenlet): N>=4 deadlocks (12 streams, greenlet serializes
  some operations reducing effective concurrency)

Requires a real VM runtime (alpine:latest image).
Run with:

    pytest tests/test_concurrent_exec.py -m integration
"""

from __future__ import annotations

import asyncio

import pytest

import boxlite

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]


async def exec_echo(box, msg: str) -> boxlite.ExecResult:
    """Execute 'echo <msg>' via the low-level Box.exec API, return ExecResult."""
    execution = await box.exec("echo", [msg])

    stdout_lines = []
    stderr_lines = []

    try:
        stdout_stream = execution.stdout()
    except Exception:
        stdout_stream = None

    try:
        stderr_stream = execution.stderr()
    except Exception:
        stderr_stream = None

    async def collect_stdout():
        if not stdout_stream:
            return
        async for line in stdout_stream:
            if isinstance(line, bytes):
                stdout_lines.append(line.decode("utf-8", errors="replace"))
            else:
                stdout_lines.append(line)

    async def collect_stderr():
        if not stderr_stream:
            return
        async for line in stderr_stream:
            if isinstance(line, bytes):
                stderr_lines.append(line.decode("utf-8", errors="replace"))
            else:
                stderr_lines.append(line)

    await asyncio.gather(collect_stdout(), collect_stderr())

    exec_result = await execution.wait()
    return boxlite.ExecResult(
        exit_code=exec_result.exit_code,
        stdout="".join(stdout_lines),
        stderr="".join(stderr_lines),
        error_message=exec_result.error_message,
    )


# ============================================================================
# CONCURRENT EXEC TESTS
# ============================================================================


class TestConcurrentExec:
    """Tests for concurrent exec() calls on a single box.

    Each test creates its own box to avoid state leakage after
    timeout-induced cancellation.

    These tests verify that multiple exec() calls can run concurrently
    without deadlocking. The known bug causes deadlock at N>=2 via
    the async API.
    """

    async def test_sequential_exec_succeeds(self, shared_runtime):
        """Baseline: sequential exec() calls always succeed."""
        opts = boxlite.BoxOptions(image="alpine:latest", auto_remove=True)
        box = await shared_runtime.create(opts)
        async with box:
            for i in range(3):
                result = await asyncio.wait_for(
                    exec_echo(box, f"hello-{i}"),
                    timeout=15,
                )
                assert result.exit_code == 0, f"exec {i} should exit 0"
                assert f"hello-{i}" in result.stdout

    async def test_concurrent_exec_2_should_not_deadlock(self, shared_runtime):
        """Bug reproduction: 2 concurrent exec() calls deadlock.

        Each exec() spawns 3 long-lived gRPC streams (send_input, attach, wait),
        all multiplexed over a single tonic Channel. At N=2 (6 concurrent streams),
        the system deadlocks permanently via the async API.

        This test uses a 30-second timeout to detect the deadlock.
        """
        opts = boxlite.BoxOptions(image="alpine:latest", auto_remove=True)
        box = await shared_runtime.create(opts)
        async with box:
            n = 2
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*[exec_echo(box, f"hello-{i}") for i in range(n)]),
                    timeout=30,
                )
            except asyncio.TimeoutError:
                pytest.fail(
                    "2 concurrent exec() calls deadlocked (timed out after 30s). "
                    "Bug: each exec() opens 3 gRPC streams; N=2 -> 6 streams "
                    "exceed single Channel capacity."
                )

            for i, result in enumerate(results):
                assert result.exit_code == 0, f"exec {i} should exit 0"
                assert f"hello-{i}" in result.stdout, (
                    f"exec {i} stdout should contain 'hello-{i}', "
                    f"got: {result.stdout!r}"
                )

    async def test_concurrent_exec_4_should_not_deadlock(self, shared_runtime):
        """4 concurrent exec() calls should not deadlock.

        Tests the originally reported threshold. Each exec() spawns 3 gRPC
        streams; N=4 -> 12 concurrent streams.
        """
        opts = boxlite.BoxOptions(image="alpine:latest", auto_remove=True)
        box = await shared_runtime.create(opts)
        async with box:
            n = 4
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*[exec_echo(box, f"hello-{i}") for i in range(n)]),
                    timeout=30,
                )
            except asyncio.TimeoutError:
                pytest.fail(
                    "4 concurrent exec() calls deadlocked (timed out after 30s). "
                    "Bug: each exec() opens 3 gRPC streams; N=4 -> 12 streams "
                    "exceed single Channel capacity."
                )

            for i, result in enumerate(results):
                assert result.exit_code == 0, f"exec {i} should exit 0"
                assert f"hello-{i}" in result.stdout, (
                    f"exec {i} stdout should contain 'hello-{i}', "
                    f"got: {result.stdout!r}"
                )

    async def test_concurrent_exec_8_should_not_deadlock(self, shared_runtime):
        """Extended test: 8 concurrent exec() calls.

        If the deadlock is fixed, this verifies the fix scales beyond
        the original threshold.
        """
        opts = boxlite.BoxOptions(image="alpine:latest", auto_remove=True)
        box = await shared_runtime.create(opts)
        async with box:
            n = 8
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*[exec_echo(box, f"hello-{i}") for i in range(n)]),
                    timeout=60,
                )
            except asyncio.TimeoutError:
                pytest.fail(
                    "8 concurrent exec() calls deadlocked (timed out after 60s)."
                )

            for i, result in enumerate(results):
                assert result.exit_code == 0, f"exec {i} should exit 0"
                assert f"hello-{i}" in result.stdout, (
                    f"exec {i} stdout should contain 'hello-{i}', "
                    f"got: {result.stdout!r}"
                )
