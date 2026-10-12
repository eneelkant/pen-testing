"""Subprocess execution helpers with timeouts and log capture."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0
    started_at: float = 0.0
    ended_at: float = 0.0
    pid: int | None = None
    log_path: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class CommandRunner:
    def __init__(self, *, max_log_bytes: int = 2_000_000):
        self.max_log_bytes = max_log_bytes

    def which(self, binary: str) -> str | None:
        from shutil import which

        return which(binary)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int | None = None,
        log_path: str | Path | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(dict(env))

        started = time.time()
        try:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd) if cwd else None,
                env=merged_env,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            ended = time.time()
            stdout = self._truncate(completed.stdout or "")
            stderr = self._truncate(completed.stderr or "")
            result = CommandResult(
                command=list(command),
                returncode=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=False,
                duration_seconds=ended - started,
                started_at=started,
                ended_at=ended,
            )
        except subprocess.TimeoutExpired as exc:
            ended = time.time()
            stdout = self._truncate(exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
            stderr = self._truncate(exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""))
            result = CommandResult(
                command=list(command),
                returncode=124,
                stdout=stdout,
                stderr=stderr + "\n[timeout]",
                timed_out=True,
                duration_seconds=ended - started,
                started_at=started,
                ended_at=ended,
            )
        except FileNotFoundError as exc:
            ended = time.time()
            result = CommandResult(
                command=list(command),
                returncode=127,
                stdout="",
                stderr=str(exc),
                timed_out=False,
                duration_seconds=ended - started,
                started_at=started,
                ended_at=ended,
            )

        if log_path:
            path = Path(log_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"$ {' '.join(result.command)}\n"
                f"exit={result.returncode} timed_out={result.timed_out}\n\n"
                f"--- stdout ---\n{result.stdout}\n\n--- stderr ---\n{result.stderr}\n",
                encoding="utf-8",
            )
            result.log_path = str(path)
        return result

    def _truncate(self, text: str) -> str:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= self.max_log_bytes:
            return text
        head = encoded[: self.max_log_bytes // 2]
        tail = encoded[-(self.max_log_bytes // 2) :]
        return (
            head.decode("utf-8", errors="replace")
            + "\n...[truncated]...\n"
            + tail.decode("utf-8", errors="replace")
        )


def terminate_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
