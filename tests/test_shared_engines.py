"""The GFAL adapters over the shared engines retain gfal2's error and callback contracts.

The engines themselves - xrdcore's pipeline, xrdhttp's connections and
``Expect: 100-continue`` - are tested in those libraries (the cases this file
held before 0.4.0 moved there); what is left is what xgfalclient adds.
"""

from __future__ import annotations

import errno
import io
from collections.abc import Callable

import pytest

import xgfalclient
from xgfalclient import GError
from xgfalclient.plugin import PluginFile
from xgfalclient.transfer import Transfer, pump


class Reader(PluginFile):
    def __init__(self) -> None:
        super().__init__("file:///source")
        self.file = io.BytesIO(b"abcdefghijkl")

    def readinto(self, buffer: memoryview | bytearray) -> int:
        return self.file.readinto(buffer)


class Writer(PluginFile):
    """A destination whose every ``write`` is ``answer``."""

    def __init__(self, answer: Callable[[bytes | bytearray | memoryview], int]) -> None:
        super().__init__("file:///target")
        self.answer = answer

    def write(self, data: bytes | bytearray | memoryview) -> int:
        return self.answer(data)


@pytest.mark.parametrize("count", [0, -1, 100])
def test_gfal_preserves_io_error_code_for_invalid_writes(
    ctx: xgfalclient.Gfal2Context, count: int
) -> None:
    transfer = Transfer(ctx, ctx.transfer_parameters(), "file:///source", "file:///target")
    writer = Writer(lambda view: count)
    with pytest.raises(GError) as caught:
        pump(transfer, Reader(), writer, buffer_size=4)
    assert caught.value.code == errno.EIO


def test_gfal_partial_writer_reports_only_committed_chunks(ctx: xgfalclient.Gfal2Context) -> None:
    transfer = Transfer(ctx, ctx.transfer_parameters(), "file:///source", "file:///target")
    received = bytearray()

    def write(view: bytes | bytearray | memoryview) -> int:
        received.extend(view[:1])
        return 1

    assert pump(transfer, Reader(), Writer(write), buffer_size=4) == 12
    assert received == b"abcdefghijkl"
    assert transfer.transferred == 12
