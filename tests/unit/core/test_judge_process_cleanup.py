from __future__ import annotations

import signal

import pytest

import wardline.core.judge_transport as judge_transport_module


class _FakeCapturePipe:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _FakeFallbackProcess:
    def __init__(self, wait_failures: list[BaseException]) -> None:
        self.pid = 4321
        self.stdout = _FakeCapturePipe()
        self.stderr = _FakeCapturePipe()
        self.wait_failures = list(wait_failures)
        self.wait_calls = 0
        self.kill_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        assert timeout is not None
        self.wait_calls += 1
        if self.wait_failures:
            raise self.wait_failures.pop(0)
        return -9

    def kill(self) -> None:
        self.kill_calls += 1


def test_bounded_finalizer_posix_fallback_survives_second_interrupt_and_transient_wait_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeFallbackProcess([OSError("TRANSIENT_WAIT_SECRET_SENTINEL")])
    group_kill_calls: list[tuple[int, int]] = []

    def _failed_termination(_process: object, *, posix: bool) -> None:
        assert _process is process
        assert posix is True
        raise OSError("PRIMARY_CLEANUP_SECRET_SENTINEL")

    def _interrupted_group_kill(pid: int, sig: int) -> None:
        group_kill_calls.append((pid, sig))
        raise KeyboardInterrupt("SECOND_INTERRUPT_SECRET_SENTINEL")

    monkeypatch.setattr(judge_transport_module, "_terminate_process_tree", _failed_termination)
    monkeypatch.setattr(judge_transport_module.os, "killpg", _interrupted_group_kill)

    with pytest.raises(OSError, match="bounded subprocess process-tree cleanup failed") as exc_info:
        judge_transport_module._finalize_bounded_process(  # type: ignore[attr-defined]
            process,  # type: ignore[arg-type]
            posix=True,
            terminate_tree=True,
            started_threads=(),
            stdout_thread=None,
            stderr_thread=None,
        )

    message = str(exc_info.value)
    assert "PRIMARY_CLEANUP_SECRET_SENTINEL" not in message
    assert "SECOND_INTERRUPT_SECRET_SENTINEL" not in message
    assert "TRANSIENT_WAIT_SECRET_SENTINEL" not in message
    assert group_kill_calls == [(4321, signal.SIGKILL)]
    assert process.kill_calls == 1
    assert process.wait_calls == 2
    assert process.stdout.close_calls == 1
    assert process.stderr.close_calls == 1


def test_bounded_finalizer_nonposix_fallback_hard_kills_and_retries_reap_after_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeFallbackProcess([KeyboardInterrupt("SECOND_INTERRUPT_SECRET_SENTINEL")])
    group_kill_calls: list[tuple[int, int]] = []

    def _interrupted_termination(_process: object, *, posix: bool) -> None:
        assert _process is process
        assert posix is False
        raise KeyboardInterrupt("PRIMARY_CLEANUP_SECRET_SENTINEL")

    monkeypatch.setattr(judge_transport_module, "_terminate_process_tree", _interrupted_termination)
    monkeypatch.setattr(
        judge_transport_module.os,
        "killpg",
        lambda pid, sig: group_kill_calls.append((pid, sig)),
    )

    with pytest.raises(OSError, match="bounded subprocess process-tree cleanup failed") as exc_info:
        judge_transport_module._finalize_bounded_process(  # type: ignore[attr-defined]
            process,  # type: ignore[arg-type]
            posix=False,
            terminate_tree=True,
            started_threads=(),
            stdout_thread=None,
            stderr_thread=None,
        )

    message = str(exc_info.value)
    assert "PRIMARY_CLEANUP_SECRET_SENTINEL" not in message
    assert "SECOND_INTERRUPT_SECRET_SENTINEL" not in message
    assert group_kill_calls == []
    assert process.kill_calls == 1
    assert process.wait_calls == 2
    assert process.stdout.close_calls == 1
    assert process.stderr.close_calls == 1
