"""The LFC test server's data: catalogue rows, identities, injections, constants.

An :class:`Entry` is one ``Cns_file_metadata`` row and a
:class:`ReplicaEntry` one ``Cns_file_replica`` row; :class:`Identity` is who
a connection turned out to be after Csec and ``getidmap``. :class:`Raw` and
:class:`Hangup` are what :meth:`~xgfalclient.testing.lfc.LFCServer.inject`
queues besides a plain status. :class:`_Fail` is how a handler reports a
serrno (and optional ``MSG_ERR`` text) to the dispatch loop.

The rows are plain mutable dataclasses because handlers edit them in place
(``chmod`` rewrites ``mode``, ``rename`` moves ``parent``/``name``) under
:attr:`LFCServer._lock <xgfalclient.testing.lfc.LFCServer>`; nothing here
locks on its own. Tests read them back through
:meth:`~xgfalclient.testing.lfc.LFCServer.lookup` to check what a request
did to the catalogue, so a field renamed here is a test change too.
"""

from __future__ import annotations

import stat as _stat
from dataclasses import dataclass, field

#: The test PKI's user, as Globus prints it.
USER_DN = "/DC=org/DC=xgfal/OU=People/CN=Test User"
#: ``Cns_srv_ping``'s answer from the EL7 build.
VERSION = "1.13.0-1"
#: Virtual ids start above the system range, as ``Cns_unique_uid`` does.
FIRST_VID = 101
#: ``CNS_TRANSTIMEOUT``: seconds a session may sit idle between requests
#: before the server gives up on it and answers ``SETIMEDOUT``.
SESSION_TIMEOUT = 60.0

# The owner's permission bits. Callers pass these to ``_check``, which
# shifts them to the group or other triplet; Cns_chkperm.c does the same.
S_IREAD, S_IWRITE, S_IEXEC = 0o400, 0o200, 0o100


@dataclass(frozen=True)
class Raw:
    """Inject bytes written to the socket as they are.

    The bytes go out instead of the handler's replies and the request's
    final status (``0``) follows them. Tests use this for what a
    well-behaved server never sends: a ``MSG_DATA`` header whose length
    exceeds ``REPBUFSZ``, or a reply missing its payload.
    """

    data: bytes


class Hangup:
    """Inject a closed connection instead of the reply.

    The server closes its socket without answering, which the client sees
    as end of stream in the middle of a request - the way a crashed or
    restarted daemon looks. Inside a session the server's next ``select``
    fails on the closed socket and the connection thread ends.
    """


#: What :meth:`LFCServer.inject` takes: a serrno to answer with, a hang-up or raw bytes.
Injection = int | Raw | Hangup


@dataclass
class Entry:
    """One ``Cns_file_metadata`` row, with its link, comment and replicas.

    ``fileid`` 2 is the root, whose ``parent`` is 0 (a pseudo-directory
    holding only ``"/"``); file ids are never reused. ``nlink`` counts a
    directory's entries, not its subdirectories plus two as POSIX does - the
    LFC's own convention, which ``rmdir`` relies on to refuse a non-empty
    directory. ``status`` is the one-character file status (``"-"`` online),
    ``csumtype`` a two-letter type (``"AD"`` for ADLER32, ``"MD"``, ``"CS"``)
    with ``csumvalue`` its hex digest. ``comment`` ``None`` means no
    ``Cns_user_metadata`` row, which ``getcomment`` reports as ``ENOENT``.
    Timestamps are whole seconds since the epoch, as ``TIME_T`` carries them.
    """

    fileid: int
    parent: int
    name: str
    mode: int
    uid: int = 0
    gid: int = 0
    guid: str = ""
    nlink: int = 0
    size: int = 0
    atime: int = 0
    mtime: int = 0
    ctime: int = 0
    fileclass: int = 0
    status: str = "-"
    csumtype: str = ""
    csumvalue: str = ""
    linkname: str = ""
    comment: str | None = None
    replicas: list[ReplicaEntry] = field(default_factory=list)

    def is_dir(self) -> bool:
        """Whether this is a directory (by the ``S_IFMT`` bits of ``mode``)."""
        return _stat.S_ISDIR(self.mode)

    def is_link(self) -> bool:
        """Whether this is a symlink; its target is then ``linkname``."""
        return _stat.S_ISLNK(self.mode)


@dataclass
class ReplicaEntry:
    """One ``Cns_file_replica`` row.

    ``sfn`` is the replica's storage URL and unique across the catalogue
    (``addreplica`` refuses a duplicate with ``EEXIST``); ``host`` is the
    storage element it lives on, which ``getreplica`` filters by.
    ``f_type`` is the file type (``"P"`` permanent), ``poolname`` and ``fs``
    the DPM placement columns, empty for an LFC.
    """

    fileid: int
    host: str
    sfn: str
    status: str = "-"
    f_type: str = "P"
    poolname: str = ""
    fs: str = ""
    nbaccesses: int = 1
    ctime: int = 0
    atime: int = 0
    ptime: int = 0


class _Fail(Exception):
    """A handler's failure: ``code`` is the serrno, ``text`` an optional ``MSG_ERR``."""

    def __init__(self, code: int, text: str = "") -> None:
        """Fail with serrno ``code``; a non-empty ``text`` goes out as ``MSG_ERR`` first."""
        super().__init__(code)
        self.code = code
        self.text = text


@dataclass
class Identity:
    """Who the connection is, once Csec and the id mapping are done.

    ``uid`` 0 is root, granted only to a trusted ``ID`` client: every
    permission check passes for it. ``gids`` lists the groups that count for
    group permissions (the VO's gid from the mapfile, first). ``name`` is
    the DN or ``"root"``, ``mech`` the Csec mechanism that established it.
    """

    uid: int
    gids: list[int]
    name: str
    mech: str

    @property
    def gid(self) -> int:
        """The primary gid, which new entries are created with."""
        return self.gids[0]
