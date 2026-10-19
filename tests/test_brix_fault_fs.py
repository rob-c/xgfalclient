"""Local copies through the external BRIX FUSE fault filesystem.

The faults every client's local copy must survive or report are checked
once, in :mod:`xrdclient.testing.brix`, and run here through
:class:`GfalLocalAdapter`: ``file://`` to ``file://`` with
``Gfal2Context.filecopy``, as a gfal2 program copies. xrdclient runs the
same suite through ``xrdclient.copy``. What only gfal2 promises - its errno
and wording - is checked by the overrides below, after the shared check.
"""

from __future__ import annotations

import errno
from pathlib import Path

from xrdclient.testing.brix import (
    BrixFaultFS,
    Kind,
    LocalCopyAdapter,
    LocalCopySuite,
    kind_of_errno,
)

import xgfalclient
from xgfalclient import GError

#: How gfal2 words a failed post-copy checksum comparison (its errno is a mere ``EIO``).
MISMATCH = "DESTINATION CHECKSUM MISMATCH"


class GfalLocalAdapter(LocalCopyAdapter):
    """``Gfal2Context.filecopy`` between two ``file://`` URLs, one context per copy."""

    def copy(
        self,
        source: Path,
        target: Path,
        *,
        verify: bool = False,
        retries: int | None = None,
        retry_interval: int = 0,
    ) -> None:
        """Copy; ``verify`` is gfal2's ``both`` adler32 check, ``retries`` its ``CONN_RETRY``."""
        context = xgfalclient.creat_context()
        try:
            if retries is not None:
                context.set_opt_integer("CORE", "CONN_RETRY", retries)
                context.set_opt_integer("CORE", "CONN_RETRY_INTERVAL", retry_interval)
            urls = (f"file://{source}", f"file://{target}")
            if verify:
                params = context.transfer_parameters()
                params.set_checksum(xgfalclient.checksum_mode.both, "adler32", "")
                context.filecopy(params, *urls)
            else:
                context.filecopy(*urls)
        finally:
            context.free()

    def kind(self, error: BaseException) -> Kind:
        """A ``GError``'s ``code`` is its errno; a checksum mismatch is known by its wording."""
        if isinstance(error, GError):
            return Kind.CORRUPT if MISMATCH in error.message else kind_of_errno(error.code)
        return super().kind(error)


class TestLocalCopy(LocalCopySuite):
    """The shared suite, plus what gfal2 alone promises about each failure."""

    seed = 31

    def make_adapter(self, filesystem: BrixFaultFS) -> LocalCopyAdapter:
        """The same adapter for every check."""
        return GfalLocalAdapter()

    def test_a_silently_dropped_write_is_caught_by_verification(self, tmp_path: Path) -> None:
        """gfal2 reports the mismatch as ``EIO``."""
        super().test_a_silently_dropped_write_is_caught_by_verification(tmp_path)
        assert isinstance(self.error, GError)
        assert self.error.code == errno.EIO

    def test_stale_recovery_refuses_to_splice_a_replaced_source(self, tmp_path: Path) -> None:
        """gfal2 says why it gave up."""
        super().test_stale_recovery_refuses_to_splice_a_replaced_source(tmp_path)
        assert isinstance(self.error, GError)
        assert "changed while recovering" in self.error.message

    def test_a_source_that_lies_about_its_size_is_not_a_success(self, tmp_path: Path) -> None:
        """The shortfall is gfal2's ``Short copy``, an ``EIO``."""
        super().test_a_source_that_lies_about_its_size_is_not_a_success(tmp_path)
        assert isinstance(self.error, GError)
        assert "Short copy" in self.error.message
        assert self.error.code == errno.EIO
