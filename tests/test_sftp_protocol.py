"""The SFTP v3 wire encoding: attributes and status-to-errno mapping."""

from __future__ import annotations

import errno

import pytest

from xgfalclient.crypto.sshkeys import Reader
from xgfalclient.plugins.sftp import protocol as fx
from xgfalclient.plugins.sftp.protocol import Attrs, StatusError, errno_for_status


def test_attrs_round_trip_full() -> None:
    attrs = Attrs(
        size=1234,
        uid=1000,
        gid=1000,
        permissions=0o100644,
        atime=111,
        mtime=222,
        extended=[(b"k@x", b"v")],
    )
    decoded = Attrs.decode(Reader(attrs.encode()))
    assert decoded == attrs


def test_attrs_round_trip_empty() -> None:
    decoded = Attrs.decode(Reader(Attrs().encode()))
    assert decoded == Attrs()
    assert decoded.size is None and decoded.permissions is None


def test_attrs_times_travel_only_as_a_pair() -> None:
    # ATTR_ACMODTIME carries both; half of it is not sent at all.
    assert Attrs(atime=111).encode() == Attrs().encode()
    assert Attrs(mtime=222).encode() == Attrs().encode()


def test_attrs_partial_uid_needs_both() -> None:
    # UID without GID is not encoded (the flag needs the pair).
    attrs = Attrs(uid=5)
    assert Attrs.decode(Reader(attrs.encode())) == Attrs()


def test_attrs_to_stat_and_type_helpers() -> None:
    dir_attrs = Attrs(permissions=0o040755, size=4096, uid=1, gid=2, atime=3, mtime=4)
    stat = dir_attrs.to_stat()
    assert stat.st_mode == 0o040755 and stat.st_size == 4096
    assert stat.st_uid == 1 and stat.st_gid == 2 and stat.st_atime == 3 and stat.st_mtime == 4
    assert stat.st_nlink == 0 and stat.st_ino == 0  # v3 carries none
    assert dir_attrs.is_dir and not dir_attrs.is_link
    link = Attrs(permissions=0o120777)
    assert link.is_link and not link.is_dir
    assert not Attrs().is_dir and not Attrs().is_link
    # to_stat with no permissions yields a zero mode.
    assert Attrs().to_stat().st_mode == 0


def test_atime_is_masked_to_32_bits() -> None:
    attrs = Attrs(atime=2**33 + 7, mtime=2**33 + 9)
    decoded = Attrs.decode(Reader(attrs.encode()))
    assert decoded.atime == 7 and decoded.mtime == 9


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (fx.FX_OK, errno.EIO),  # OK is never mapped as an error, but the table default holds
        (fx.FX_NO_SUCH_FILE, errno.ENOENT),
        (fx.FX_PERMISSION_DENIED, errno.EACCES),
        (fx.FX_FAILURE, errno.EIO),
        (fx.FX_BAD_MESSAGE, errno.EINVAL),
        (fx.FX_NO_CONNECTION, errno.ENOTCONN),
        (fx.FX_CONNECTION_LOST, errno.ECONNRESET),
        (fx.FX_OP_UNSUPPORTED, errno.ENOSYS),
        (11, errno.EEXIST),
        (18, errno.ENOTEMPTY),
        (19, errno.ENOTDIR),
        (24, errno.EISDIR),
        (999, errno.EIO),  # unknown -> EIO
    ],
)
def test_errno_for_status(status: int, code: int) -> None:
    assert errno_for_status(status) == code


def test_status_error_message_and_errno() -> None:
    exc = StatusError(fx.FX_NO_SUCH_FILE, "No such file")
    assert exc.code == fx.FX_NO_SUCH_FILE
    assert exc.errno == errno.ENOENT
    assert str(exc) == "No such file"
    # Default message comes from the status name table.
    assert StatusError(fx.FX_PERMISSION_DENIED).message == "PERMISSION_DENIED"
    assert StatusError(999).message == "status 999"
