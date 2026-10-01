"""Lifecycle wrapper for the external BRIX fault-injection proxy."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time

import pytest


def binary() -> str:
    """The requested BRIX proxy, or skip an opt-in integration test."""
    found = os.environ.get("BRIX_FAULT_PROXY") or shutil.which("brix-fault-proxy")
    if found is None:
        pytest.skip("set BRIX_FAULT_PROXY or install brix-fault-proxy")
    return found


def _port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        return int(listener.getsockname()[1])


class BrixProxy:
    """A deterministic BRIX proxy with live control-port access."""

    def __init__(self, target_port: int, *, seed: int = 1) -> None:
        self.binary = binary()
        self.listen_port = _port()
        self.control_port = _port()
        while self.control_port == self.listen_port:
            self.control_port = _port()
        self.target_port = target_port
        self.seed = seed
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> BrixProxy:
        self.process = subprocess.Popen(
            [
                self.binary,
                "--listen",
                str(self.listen_port),
                "--target",
                f"127.0.0.1:{self.target_port}",
                "--control",
                str(self.control_port),
                "--seed",
                str(self.seed),
                "--quiet",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout is not None else ""
                raise RuntimeError(f"brix-fault-proxy exited during startup: {output}")
            try:
                with socket.create_connection(("127.0.0.1", self.control_port), timeout=0.1):
                    return self
            except OSError:
                time.sleep(0.02)
        raise RuntimeError("brix-fault-proxy control port did not start")

    def __exit__(self, *exc: object) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)

    def command(self, command: str) -> str:
        completed = subprocess.run(
            [self.binary, "ctl", f"127.0.0.1:{self.control_port}", command],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr or completed.stdout)
        return completed.stdout
