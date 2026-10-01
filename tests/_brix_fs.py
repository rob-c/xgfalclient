"""Lifecycle wrapper for the external BRIX FUSE fault filesystem."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, cast

import pytest


def binary() -> str:
    """The requested BRIX fault filesystem, or skip an opt-in test."""
    found = os.environ.get("BRIX_FAULT_FS") or shutil.which("brix-fault-fs")
    if found is None:
        pytest.skip("set BRIX_FAULT_FS or install brix-fault-fs")
    return found


def _unmount(path: Path) -> None:
    """Unmount through the host's unprivileged FUSE command."""
    candidates = (
        ["umount", str(path)],
        ["fusermount3", "-u", str(path)],
        ["fusermount", "-u", str(path)],
    )
    for command in candidates:
        if shutil.which(command[0]) is None:
            continue
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if completed.returncode == 0:
            return


class BrixFaultFS:
    """A disposable directory-backed fault filesystem with live controls."""

    def __init__(self, parent: Path, *, seed: int = 31) -> None:
        self.binary = binary()
        self.backing = parent / "backing"
        self.mount = parent / "mount"
        self.backing.mkdir()
        self.mount.mkdir()
        (self.backing / ".ready").touch()
        self._control_dir = Path(tempfile.mkdtemp(prefix="brix-fs-", dir="/tmp"))
        self.control = self._control_dir / "control.sock"
        self.seed = seed
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> BrixFaultFS:
        self.process = subprocess.Popen(
            [
                self.binary,
                "--root",
                str(self.backing),
                "--mount",
                str(self.mount),
                "--control",
                str(self.control),
                "--seed",
                str(self.seed),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout is not None else ""
                self.__exit__()
                raise RuntimeError(f"brix-fault-fs exited during startup: {output}")
            try:
                if self.control.exists() and (self.mount / ".ready").exists():
                    return self
            except OSError:
                pass
            time.sleep(0.05)
        self.__exit__()
        raise RuntimeError("brix-fault-fs mount did not become ready")

    def __exit__(self, *exc: object) -> None:
        process, self.process = self.process, None
        if process is not None:
            if process.poll() is None:
                try:
                    self.command("clear")
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    pass
                _unmount(self.mount)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        shutil.rmtree(self._control_dir, ignore_errors=True)

    def command(self, command: str) -> dict[str, Any]:
        """Run one live control command and return its JSON reply."""
        completed = subprocess.run(
            [self.binary, "--ctl", str(self.control), command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr or completed.stdout)
        return cast("dict[str, Any]", json.loads(completed.stdout))

    def configure(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Atomically replace the live fault policy."""
        return self.command(f"configure {json.dumps(policy, separators=(',', ':'))}")
