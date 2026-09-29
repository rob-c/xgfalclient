"""``gfal-copy``'s progress bar, redrawn twice a second on one terminal line::

    Copying file:///a..  3s  42% [=========>             ] 12.34MB 4.11MB/s

Adapted from gfal2-util 1.9.1's ``progress.py`` (Apache-2.0, (c) CERN): the
layout, units and rounding are the same; the thread handling is simpler (the
final line is drawn under the lock, so the redraw thread cannot interleave).
"""

from __future__ import annotations

import math
import os
import sys
import threading
import time
from typing import Any

__all__ = ["Progress"]

#: Seconds between redraws.
INTERVAL = 0.5


def _width() -> int:
    """The terminal's width (from stdin, as gfal2-util asks), else 80."""
    try:
        return os.get_terminal_size(sys.stdin.fileno()).columns
    except (AttributeError, OSError, ValueError):
        return 80


def rate_str(rate: float) -> str:
    """``512B/s``, ``1.21K/s``, ``12.3M/s``, ``123G/s``: three significant digits."""
    symbols = ["B", "K", "M", "G", "T", "P"]
    degree = 0
    while float(rate) >= 1024.0 and degree < len(symbols) - 1:
        rate = float(rate) / 1024.0
        degree += 1
    digits = len(str(math.floor(rate)))
    precision = 3 - digits if digits < 3 and degree != 0 else 0
    return f"{round(rate, precision):0.{precision}f}{symbols[degree]}/s"


def size_str(size: float) -> str:
    """``rate_str`` without the ``/s``, and always ending in ``B``."""
    text = rate_str(size)[:-2]
    return text if text.endswith("B") else text + "B"


class Progress:
    """One file's progress bar; :meth:`update` from the monitor callback."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.started = False
        self.stopped = False
        self.status: dict[str, Any] | None = None
        self.lock = threading.Lock()
        self.dots = 0
        self.start_time = time.monotonic()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        with self.lock:
            # stop() does nothing before start(), so stopped implies started.
            if self.started:
                raise RuntimeError("progress bar already started")
            self.started = True
            self.start_time = time.monotonic()
        self.thread = threading.Thread(target=self._run, name="gfal-progress", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while True:
            with self.lock:
                if self.stopped:
                    return
                self._update()
            time.sleep(INTERVAL)

    def _elapsed(self) -> int:
        return int(time.monotonic() - self.start_time)

    def _update(self) -> None:
        """Label, elapsed time, then as much as is known: percentage and bar, size, rate."""
        write = sys.stdout.write
        write("\r")
        label = self.label + ("." * self.dots).ljust(3)
        elapsed = f"  {self._elapsed()}s "
        write(label)
        write(elapsed)
        status = self.status
        if status:
            width = _width()
            if status.get("percentage"):
                percentage = f"{round(status['percentage'])}% "
                rate = rate_str(status["rate"])
                size = f" {size_str(status['curr_size'])} "
                unused = width - len(label) - len(elapsed) - len(percentage) - len(size) - len(rate)
                bar_width = unused - 2 if unused >= 7 else 5
                bars = max(1, round(status["percentage"] * bar_width / 100.0))
                write(percentage)
                write("[" + "=" * (bars - 1) + ">" + " " * (unused - bars - 2) + "]")
                write(size)
                write(rate)
            elif status.get("total_size"):
                size = f" File size: {size_str(status['total_size'])}"
                write(size)
                write(" " * (width - len(label) - len(elapsed) - len(size)))
            elif status.get("curr_size"):
                rate = rate_str(status["rate"]) if status.get("rate") else ""
                size = size_str(status["curr_size"]) + " "
                write(" " * (width - len(label) - len(elapsed) - len(size) - len(rate)))
                write(size)
                write(rate)
            else:
                write(" " * (width - len(label) - len(elapsed)))
        sys.stdout.flush()
        self.dots = (self.dots + 1) % 4

    def update(
        self,
        curr_size: int | None = None,
        total_size: int | None = None,
        rate: float | None = None,
        time_elapsed: int | None = None,
    ) -> None:
        status: dict[str, Any] = {}
        if curr_size:
            status["curr_size"] = curr_size
        if total_size:
            status["total_size"] = total_size
        if curr_size and time_elapsed and total_size:
            status["rate"] = float(curr_size) / float(time_elapsed)
            status["percentage"] = float(curr_size) / float(total_size) * 100.0
        elif rate:
            status["rate"] = rate
        with self.lock:
            self.status = status

    def stop(self, success: bool) -> None:
        """Draw the final ``[DONE]``/``[FAILED]`` line; later calls do nothing."""
        with self.lock:
            if not self.started or self.stopped:
                return
            self.stopped = True
            message = (
                f"{self.label}   [{'DONE' if success else 'FAILED'}]  after {self._elapsed()}s"
            )
            sys.stdout.write("\r" + message + " " * (_width() - len(message)))
            sys.stdout.flush()
