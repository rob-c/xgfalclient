"""One function per Cns request type, and the table that dispatch reads (``Cns_procreq.c``).

Every handler has the :data:`Handler` signature: the connection, the
caller's :class:`~.model.Identity`, the request's magic (the protocol
revision, which changes some layouts) and an :class:`Unpacker` positioned
after the client's own uid and gid. It answers through the connection and
returns the status ``CNS_RC``/``CNS_IRC`` carries, or raises
:class:`~.model._Fail`. :data:`_HANDLERS` maps request types to handlers;
the facade re-exports this very dict, so a test may replace an entry.

Handlers run with the server's lock held, one at a time across all
connections, so they read and change the catalogue freely; they must not
block. The body layouts in each docstring are what follows the client's
uid and gid, in the marshalling of :mod:`xgfalclient.plugins.lfc.wire`
(``STRING`` is NUL-terminated); paths are read with
:func:`~.namespace._path`, which applies ``MAXPATHLEN`` (1023 bytes).
Request types not in the table (``SETFSIZE`` by file id,
``STARTTRANS``/``ENDTRANS``, ACLs and the rest) get ``SEOPNOTSUP`` with an
``NS003 - illegal function`` message.

To model another request: write ``_h_<name>`` with the :data:`Handler`
signature, read the body in the order ``Cns_procreq.c`` does, raise
:class:`~.model._Fail` with the serrno the real server returns, answer
with :meth:`~.connection._Connection.reply`, and add it to
:data:`_HANDLERS` - plus a re-export in :mod:`xgfalclient.testing.lfc` if
tests import it by name.
"""

from __future__ import annotations

import errno
import stat as _stat
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

from ...errors import GError
from ...plugins.lfc import wire
from ...plugins.lfc.wire import Packer, Unpacker
from .model import S_IREAD, S_IWRITE, VERSION, Entry, Identity, ReplicaEntry, _Fail
from .namespace import (
    _EXISTING,
    _EXISTING_LINK,
    _NEW_NAME,
    _REMOVABLE,
    _by_guid,
    _check,
    _chkback,
    _parse,
    _path,
    _path_of,
    _remove,
    _stat_record,
    _statg_record,
    _sticky,
    _Want,
    _writable,
)

if TYPE_CHECKING:
    from ..lfc import LFCServer
    from .connection import _Connection

#: What every handler looks like; a string forward reference, as
#: :class:`~.connection._Connection` imports this module.
Handler = Callable[["_Connection", Identity, int, Unpacker], int]


def _stat_common(conn: _Connection, ident: Identity, reader: Unpacker, nofollow: bool) -> int:
    """``Cns_srv_stat``/``Cns_srv_lstat``: body ``HYPER cwd, HYPER fileid, STRING path``.

    A non-zero ``fileid`` wins over the path: the row is fetched directly and
    only the ancestors' search permission is checked (``Cns_chkbackperm``), as
    for a lookup by id the server has no path to walk. The reply is one
    ``MSG_DATA`` holding a :func:`~.namespace._stat_record`. ``nofollow`` is
    the ``lstat`` difference: a symlink in the last place is described itself.
    """
    cwd, fileid, path = reader.hyper(), reader.hyper(), _path(reader)
    if fileid:
        entry = conn.server.entries.get(fileid)
        if entry is None:
            raise _Fail(errno.ENOENT)
        _chkback(conn.server, entry.parent, ident)
    else:
        _, entry = _parse(conn.server, ident, cwd, path, _Want(must_exist=True, nofollow=nofollow))
    packer = Packer()
    _stat_record(packer, entry)
    conn.reply(wire.MSG_DATA, packer.bytes())
    return 0


def _h_stat(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_stat``: the entry a path names, symlinks followed."""
    return _stat_common(conn, ident, reader, False)


def _h_lstat(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_lstat``: like ``stat``, but a final symlink is described itself."""
    return _stat_common(conn, ident, reader, True)


def _h_statg(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_statg``: body ``HYPER cwd, STRING path, STRING guid``; a ``statg`` record.

    The path is used when there is one, and a GUID sent alongside it must
    then match the entry's (``EINVAL`` with ``MSG_ERR`` "GUID mismatch");
    with no path the GUID alone finds the entry, and with neither the answer
    is ``ENOENT``. The GUID lookup checks no ancestor permission, unlike the
    replica requests below.
    """
    cwd, path = reader.hyper(), _path(reader)
    guid = reader.string()
    if path:
        _, entry = _parse(conn.server, ident, cwd, path, _EXISTING)
        if guid and guid != entry.guid:
            raise _Fail(errno.EINVAL, "GUID mismatch\n")
    else:
        if not guid:
            raise _Fail(errno.ENOENT)
        entry = _by_guid(conn.server, guid)
    packer = Packer()
    _statg_record(packer, entry)
    conn.reply(wire.MSG_DATA, packer.bytes())
    return 0


def _h_statr(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_statr``: body ``STRING sfn``; the ``statg`` record of the file owning that replica.

    ``ENOENT`` when no entry has a replica with exactly that SFN. No
    permission is checked.
    """
    sfn = reader.string()
    for entry in conn.server.entries.values():
        if any(replica.sfn == sfn for replica in entry.replicas):
            packer = Packer()
            _statg_record(packer, entry)
            conn.reply(wire.MSG_DATA, packer.bytes())
            return 0
    raise _Fail(errno.ENOENT)


def _h_access(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_access``: body ``HYPER cwd, STRING path, LONG amode``.

    ``amode`` is ``access(2)``'s ``R_OK``/``W_OK``/``X_OK`` (4/2/1) or ``F_OK``
    (0, existence only); any other bit is ``EINVAL``. Shifting it left by six
    turns it into owner bits for :func:`~.namespace._check`, which answers
    ``EACCES``. No ``MSG_DATA``: the status is the answer.
    """
    cwd, path, amode = reader.hyper(), _path(reader), reader.long()
    if amode & ~7:
        raise _Fail(errno.EINVAL)
    _, entry = _parse(conn.server, ident, cwd, path, _EXISTING)
    if amode:
        _check(entry, (amode & 7) << 6, ident)
    return 0


def _h_chmod(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_chmod``: body ``HYPER cwd, STRING path, LONG mode``.

    Only the owner or root may change the mode (``EPERM``). As ``chmod(2)``
    does for unprivileged callers, the sticky bit is dropped on anything
    but a directory and set-gid is dropped unless the caller is in the
    entry's group. The file-type bits are kept, and ``ctime`` moves.
    """
    _writable(conn)
    cwd, path, mode = reader.hyper(), _path(reader), reader.long()
    _, entry = _parse(conn.server, ident, cwd, path, _EXISTING)
    if ident.uid not in (entry.uid, 0):
        raise _Fail(errno.EPERM)
    if not entry.is_dir() and ident.uid:
        mode &= ~_stat.S_ISVTX
    if ident.uid and entry.gid not in ident.gids:
        mode &= ~_stat.S_ISGID
    entry.mode = _stat.S_IFMT(entry.mode) | (mode & 0o7777)
    entry.ctime = int(time.time())
    return 0


def _new_entry(conn: _Connection, ident: Identity, reader: Unpacker, magic: int, kind: int) -> int:
    """``Cns_srv_mkdir`` and ``Cns_srv_creat``, which differ only in details.

    Body: ``WORD umask, HYPER cwd, STRING path, LONG mode`` and, from
    ``CNS_MAGIC2`` (``Cns_mkdirg``/``Cns_creatg``), ``STRING guid``, which must
    parse as a UUID (``EINVAL``). ``kind`` (``wire.MKDIR`` or ``wire.CREAT``)
    picks the variant:

    * ``mkdir`` does not follow a symlink in the last place, so it reports an
      existing link as ``EEXIST``; ``creat`` follows it and acts on the target.
    * An existing name is ``EEXIST`` for ``mkdir``. ``creat`` of an existing
      file truncates it - size and checksum cleared - but only when the GUID
      matches and it has no replicas (``EEXIST`` otherwise) and the caller may
      write it (``EACCES``); an existing directory is ``EISDIR``.
    * A new file needs a GUID (``EINVAL``): the LFC catalogues files by GUID,
      and only ``mkdir`` makes one up when none is sent.

    The new entry gets ``mode & 0o7777`` less the client's umask, the
    caller's uid and primary gid, or the parent's gid when the parent is
    set-gid (a new directory inherits the set-gid bit too, as on Unix).
    ``creat`` answers ``MSG_DATA`` with the new ``HYPER fileid``; ``mkdir``
    only with its status.
    """
    _writable(conn)
    mask, cwd, path, mode = reader.word(), reader.hyper(), _path(reader), reader.long()
    guid = _new_guid(reader, magic)
    directory = kind == wire.MKDIR
    above, entry = _parse(conn.server, ident, cwd, path, _Want(nofollow=directory, parent=True))
    if entry.name == "/":
        raise _Fail(errno.EEXIST if directory else errno.EISDIR)
    assert above is not None
    if entry.fileid:
        if directory:
            raise _Fail(errno.EEXIST)
        _truncate(entry, guid, ident)
    else:
        if not directory and not guid:
            raise _Fail(errno.EINVAL)  # the LFC insists on a GUID
        entry = _create(conn, ident, above, entry.name, (mode & 0o7777) & ~mask, guid, directory)
    if not directory:
        conn.reply(wire.MSG_DATA, Packer().hyper(entry.fileid).bytes())
    return 0


def _new_guid(reader: Unpacker, magic: int) -> str:
    """The ``STRING guid`` a ``CNS_MAGIC2`` ``mkdir``/``creat`` carries, else ``""``.

    One that does not parse as a UUID is ``EINVAL``.
    """
    guid = reader.string() if magic >= wire.MAGIC2 else ""
    if guid:
        try:
            uuid.UUID(guid)
        except ValueError as exc:
            raise _Fail(errno.EINVAL) from exc
    return guid


def _truncate(entry: Entry, guid: str, ident: Identity) -> None:
    """``creat`` of an existing ``entry``: clear its size and checksum.

    A directory is ``EISDIR``; another GUID or a file with replicas is
    ``EEXIST``; the caller must be allowed to write it (``EACCES``).
    """
    if entry.is_dir():
        raise _Fail(errno.EISDIR)
    if entry.guid != guid:
        raise _Fail(errno.EEXIST)
    _check(entry, S_IWRITE, ident)
    if entry.replicas:
        raise _Fail(errno.EEXIST)
    entry.size, entry.csumtype, entry.csumvalue = 0, "", ""
    entry.mtime = entry.ctime = int(time.time())


def _create(
    conn: _Connection,
    ident: Identity,
    above: Entry,
    name: str,
    permissions: int,
    guid: str,
    directory: bool,
) -> Entry:
    """Make and insert the new file or directory ``name`` in ``above``.

    Owned by the caller's uid and primary gid, or the parent's gid when the
    parent is set-gid (a new directory inherits the set-gid bit too, as on
    Unix). A directory sent no GUID is given a fresh one.
    """
    now = int(time.time())
    kind_bits = _stat.S_IFDIR if directory else _stat.S_IFREG
    entry = Entry(
        conn.server._new_id(),
        above.fileid,
        name,
        kind_bits | permissions,
        ident.uid,
        ident.gid,
        guid=guid or str(uuid.uuid4()),
        nlink=0 if directory else 1,
        atime=now,
        mtime=now,
        ctime=now,
    )
    if above.mode & _stat.S_ISGID:
        entry.gid = above.gid
        if directory:
            entry.mode |= _stat.S_ISGID
    conn.server._insert(above, entry)
    return entry


def _h_mkdir(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_mkdir``: see :func:`_new_entry`."""
    return _new_entry(conn, ident, reader, magic, wire.MKDIR)


def _h_creat(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_creat``: see :func:`_new_entry`."""
    return _new_entry(conn, ident, reader, magic, wire.CREAT)


def _h_rmdir(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_rmdir``: body ``HYPER cwd, STRING path``.

    The root is ``EINVAL``, a non-directory ``ENOTDIR``, and a directory with
    entries ``EEXIST`` - the LFC's errno for this, not ``ENOTEMPTY``. A
    symlink to a directory is not followed, so it is ``ENOTDIR`` too. Write
    permission on the parent comes from the lookup, the sticky-bit rule from
    :func:`~.namespace._sticky`.
    """
    _writable(conn)
    cwd, path = reader.hyper(), _path(reader)
    above, entry = _parse(conn.server, ident, cwd, path, _REMOVABLE)
    if entry.name == "/":
        raise _Fail(errno.EINVAL)
    if not entry.is_dir():
        raise _Fail(errno.ENOTDIR)
    if entry.nlink:
        raise _Fail(errno.EEXIST)
    assert above is not None
    _sticky(above, entry, ident)
    _remove(conn.server, above, entry)
    return 0


def _unlink_one(conn: _Connection, ident: Identity, cwd: int, path: str, force: bool) -> int:
    """``unlinkonefile``; returns a status rather than raising, for ``DELFILES``.

    A directory is ``EPERM``, as ``unlink(2)`` has it; a file that still has
    replicas is ``EEXIST`` unless ``force`` - the catalogue refuses to lose
    track of data that exists somewhere. A symlink is removed, never its
    target.
    """
    try:
        above, entry = _parse(conn.server, ident, cwd, path, _REMOVABLE)
        if entry.name == "/":
            raise _Fail(errno.EINVAL)
        if entry.is_dir():
            raise _Fail(errno.EPERM)
        assert above is not None
        _sticky(above, entry, ident)
        if entry.replicas and not force:
            raise _Fail(errno.EEXIST)
        _remove(conn.server, above, entry)
    except _Fail as exc:
        return exc.code
    return 0


def _h_unlink(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_unlink``: body ``HYPER cwd, STRING path``; see :func:`_unlink_one`."""
    _writable(conn)
    cwd, path = reader.hyper(), _path(reader)
    return _unlink_one(conn, ident, cwd, path, False)


def _h_delfiles(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_delfiles``: remove many paths in one request, one status each.

    Body: ``WORD argtype, WORD force``, ``HYPER cwd`` when ``argtype`` is 1,
    ``LONG count``, then ``count`` path strings. Only ``argtype`` 1 (a list of
    paths) is modelled; another type, or a count below 1, is ``EINVAL`` for
    the whole request. A path that fails to unmarshall does not stop the
    rest: its status is recorded and the next path read. The answer is a
    ``MSG_STATUSES`` of ``LONG`` statuses in request order, then ``MSG_DATA``
    with ``LONG count``; the request itself succeeds even if every path failed.
    """
    _writable(conn)
    argtype, force = reader.word(), reader.word()
    cwd = reader.hyper() if argtype == 1 else 0
    count = reader.long()
    if count <= 0 or argtype != 1:
        raise _Fail(errno.EINVAL)
    statuses = Packer()
    for _ in range(count):
        try:
            path = _path(reader)
        except _Fail as exc:
            statuses.long(exc.code)
            continue
        statuses.long(_unlink_one(conn, ident, cwd, path, bool(force)))
    conn.reply(wire.MSG_STATUSES, statuses.bytes())
    conn.reply(wire.MSG_DATA, Packer().long(count).bytes())
    return 0


def _h_rename(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_rename``: body ``HYPER cwd, STRING old, STRING new``.

    Neither name's final symlink is followed, and both parents need write
    permission. Renaming an entry onto itself is a no-op, as in
    ``rename(2)``. The rules after that:

    * the root cannot be moved or replaced (``EINVAL``), nor can a directory
      move into its own subtree (``EINVAL``, found by walking up from the
      target's parent);
    * an existing target is replaced only by an entry of the same kind
      (file over directory ``EISDIR``, directory over file ``ENOTDIR``), if it
      is an empty directory or a file without replicas (``EEXIST``), and if
      the sticky-bit rule lets the caller remove it;
    * moving a directory needs write permission on the directory itself,
      whose ``..`` changes.

    The move is done in place: the row keeps its file id, GUID and replicas.
    """
    _writable(conn)
    server = conn.server
    cwd, old, new = reader.hyper(), _path(reader), _path(reader)
    old_parent, source = _parse(server, ident, cwd, old, _REMOVABLE)
    new_parent, target = _parse(server, ident, cwd, new, _NEW_NAME)
    if source.fileid == target.fileid:
        return 0
    if source.name == "/" or target.name == "/":
        raise _Fail(errno.EINVAL)
    assert old_parent is not None  # only the root has no parent
    assert new_parent is not None
    if source.is_dir():
        _refuse_own_subtree(server, source, target)
    if target.fileid:
        _check_replaceable(new_parent, source, target, ident)
    if source.is_dir():
        _check(source, S_IWRITE, ident)
    _sticky(old_parent, source, ident)
    if target.fileid:
        _remove(server, new_parent, target)
    _relink(server, old_parent, new_parent, source, target.name)
    return 0


def _refuse_own_subtree(server: LFCServer, source: Entry, target: Entry) -> None:
    """``EINVAL`` if directory ``source`` would become its own descendant at ``target``.

    Walks up from where it would land and refuses if it meets ``source``.
    """
    walk = target.parent
    while walk:
        if walk == source.fileid:
            raise _Fail(errno.EINVAL)
        walk = server.entries[walk].parent


def _check_replaceable(new_parent: Entry, source: Entry, target: Entry, ident: Identity) -> None:
    """Whether ``source`` may replace the existing ``target`` in ``new_parent``.

    Only an entry of the same kind (file over directory ``EISDIR``, directory
    over file ``ENOTDIR``), only an empty directory or a file without
    replicas (``EEXIST``), and only as the sticky-bit rule allows.
    """
    if not source.is_dir() and target.is_dir():
        raise _Fail(errno.EISDIR)
    if source.is_dir() and not target.is_dir():
        raise _Fail(errno.ENOTDIR)
    if target.is_dir() and target.nlink:
        raise _Fail(errno.EEXIST)
    if target.replicas:
        raise _Fail(errno.EEXIST)
    _sticky(new_parent, target, ident)


def _relink(
    server: LFCServer, old_parent: Entry, new_parent: Entry, source: Entry, name: str
) -> None:
    """Move the row ``source`` itself to ``name`` in ``new_parent``.

    Its file id, GUID and replicas survive the move; the parents' ``nlink``
    and the old parent's times change.
    """
    del server.children[old_parent.fileid][source.name]
    old_parent.nlink -= 1
    source.parent, source.name = new_parent.fileid, name
    server.children[new_parent.fileid][source.name] = source.fileid
    new_parent.nlink += 1
    source.ctime = old_parent.mtime = old_parent.ctime = int(time.time())


def _h_symlink(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_symlink``: body ``HYPER cwd, STRING target, STRING linkname``.

    The target is stored as given and never resolved, so dangling links are
    fine. The link is mode ``0o777``, owned by the caller, with the parent's
    gid in a set-gid directory. An existing name is ``EEXIST``.
    """
    _writable(conn)
    cwd, target, link = reader.hyper(), _path(reader), _path(reader)
    above, entry = _parse(conn.server, ident, cwd, link, _NEW_NAME)
    if entry.fileid:
        raise _Fail(errno.EEXIST)
    assert above is not None
    now = int(time.time())
    created = Entry(
        conn.server._new_id(),
        above.fileid,
        entry.name,
        _stat.S_IFLNK | 0o777,
        ident.uid,
        above.gid if above.mode & _stat.S_ISGID else ident.gid,
        nlink=1,
        atime=now,
        mtime=now,
        ctime=now,
        linkname=target,
    )
    conn.server._insert(above, created)
    return 0


def _h_readlink(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_readlink``: body ``HYPER cwd, STRING path``; ``MSG_DATA`` the target.

    The path's last component is not followed; anything but a symlink is
    ``EINVAL``, as ``readlink(2)`` says. Non-owners need read permission.
    """
    cwd, path = reader.hyper(), _path(reader)
    _, entry = _parse(conn.server, ident, cwd, path, _EXISTING_LINK)
    if ident.uid != entry.uid:
        _check(entry, S_IREAD, ident)
    if not entry.is_link():
        raise _Fail(errno.EINVAL)
    conn.reply(wire.MSG_DATA, Packer().string(entry.linkname).bytes())
    return 0


def _h_getcomment(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_getcomment``: body ``HYPER cwd, STRING path``; ``MSG_DATA`` the comment.

    Non-owners need read permission. An entry with no comment is ``ENOENT``.
    """
    cwd, path = reader.hyper(), _path(reader)
    _, entry = _parse(conn.server, ident, cwd, path, _EXISTING)
    if ident.uid != entry.uid:
        _check(entry, S_IREAD, ident)
    if entry.comment is None:
        raise _Fail(errno.ENOENT)
    conn.reply(wire.MSG_DATA, Packer().string(entry.comment).bytes())
    return 0


def _h_setcomment(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_setcomment``: body ``HYPER cwd, STRING path, STRING comment``.

    A comment over ``MAXCOMMENTLEN`` (255) bytes is ``EINVAL``. Non-owners
    need write permission. An empty comment deletes the row, so a later
    ``getcomment`` is ``ENOENT`` again.
    """
    _writable(conn)
    cwd, path = reader.hyper(), _path(reader)
    try:
        comment = reader.string(wire.MAXCOMMENTLEN)
    except GError as exc:
        raise _Fail(errno.EINVAL) from exc
    _, entry = _parse(conn.server, ident, cwd, path, _EXISTING)
    if ident.uid != entry.uid:
        _check(entry, S_IWRITE, ident)
    entry.comment = comment or None
    return 0


def _h_setfsizeg(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_setfsizeg``: record a file's size and checksum, by GUID.

    Body: ``STRING guid, HYPER size, STRING csumtype, STRING csumvalue``; the
    type is at most 2 characters and must be ``CS``, ``AD`` or ``MD`` when
    given, the value at most 32. A size with the top bit set (negative as a
    signed 64-bit value) is ``EINVAL``. The ancestors need search
    permission, a directory is ``EISDIR``, and non-owners need write
    permission. ``mtime`` and ``ctime`` move.
    """
    _writable(conn)
    guid, size = reader.string(), reader.hyper()
    try:
        csumtype, csumvalue = reader.string(2), reader.string(32)
    except GError as exc:
        raise _Fail(errno.EINVAL) from exc
    if size >> 63 or (csumtype and csumtype not in ("CS", "AD", "MD")):
        raise _Fail(errno.EINVAL)
    entry = _by_guid(conn.server, guid)
    _chkback(conn.server, entry.parent, ident)
    if entry.is_dir():
        raise _Fail(errno.EISDIR)
    if ident.uid != entry.uid:
        _check(entry, S_IWRITE, ident)
    entry.size, entry.csumtype, entry.csumvalue = size, csumtype, csumvalue
    entry.mtime = entry.ctime = int(time.time())
    return 0


def _h_addreplica(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_addreplica``: register a replica of a file, by file id or GUID.

    Body: ``HYPER fileid, STRING guid, STRING host, STRING sfn``; from
    ``CNS_MAGIC2`` ``BYTE status``, from ``CNS_MAGIC3`` ``BYTE f_type``, then
    (``MAGIC2``) ``STRING poolname`` and (``MAGIC3``) ``STRING fs``. Fields a
    ``CNS_MAGIC4`` request adds after those are not read - nothing follows them.
    A non-zero ``fileid`` wins; otherwise the GUID must name the file
    (``ENOENT``). Host and SFN are required (``EINVAL``), the SFN must be new
    anywhere in the catalogue (``EEXIST``), and a directory is ``EISDIR``.
    Non-owners need only read permission on the file, not write, plus
    search permission on its ancestors.
    """
    _writable(conn)
    fileid, guid, host, sfn = reader.hyper(), reader.string(), reader.string(), reader.string()
    status, f_type, pool, fs = _replica_columns(reader, magic)
    if not host or not sfn:
        raise _Fail(errno.EINVAL)
    entry = _by_id_or_guid(conn.server, fileid, guid)
    _chkback(conn.server, entry.parent, ident)
    if ident.uid != entry.uid:
        _check(entry, S_IREAD, ident)
    if entry.is_dir():
        raise _Fail(errno.EISDIR)
    for other in conn.server.entries.values():
        if any(replica.sfn == sfn for replica in other.replicas):
            raise _Fail(errno.EEXIST)
    now = int(time.time())
    entry.replicas.append(
        ReplicaEntry(entry.fileid, host, sfn, status, f_type, pool, fs, 1, now, now)
    )
    return 0


def _replica_columns(reader: Unpacker, magic: int) -> tuple[str, str, str, str]:
    """An ``addreplica``'s ``(status, f_type, poolname, fs)``, as far as ``magic`` sends them.

    ``CNS_MAGIC2`` adds the status and pool, ``CNS_MAGIC3`` the file type and
    filesystem; an older request has status ``"-"`` and the rest empty.
    """
    if magic < wire.MAGIC2:
        return "-", "", "", ""
    status = reader.char()
    f_type = reader.char() if magic >= wire.MAGIC3 else ""
    pool = reader.string()
    fs = reader.string() if magic >= wire.MAGIC3 else ""
    return status, f_type, pool, fs


def _by_id_or_guid(server: LFCServer, fileid: int, guid: str) -> Entry:
    """The entry a non-zero ``fileid`` names, else the one ``guid`` does; ``ENOENT`` for none."""
    if fileid:
        entry = server.entries.get(fileid)
        if entry is None:
            raise _Fail(errno.ENOENT)
        return entry
    if not guid:
        raise _Fail(errno.ENOENT)
    return _by_guid(server, guid)


def _h_delreplica(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_delreplica``: body ``HYPER fileid, STRING guid, STRING sfn``.

    The SFN finds the file owning the replica (``ENOENT`` if none). A file id
    or GUID sent too must name that same file, else ``ENOENT``; the named
    file's ancestors are checked for search permission first, so an
    unreachable file is ``EACCES`` even when it is the wrong one. Non-owners need
    write permission. The file's size is then taken off its ancestors by
    :func:`_account`.
    """
    _writable(conn)
    fileid, guid, sfn = reader.hyper(), reader.string(), reader.string()
    owner = next(
        (e for e in conn.server.entries.values() if any(r.sfn == sfn for r in e.replicas)), None
    )
    if owner is None:
        raise _Fail(errno.ENOENT)
    if fileid:
        entry = conn.server.entries.get(fileid)
        if entry is None:
            raise _Fail(errno.ENOENT)
    elif guid:
        entry = _by_guid(conn.server, guid)
    else:
        entry = owner
    _chkback(conn.server, entry.parent, ident)
    if entry is not owner:
        raise _Fail(errno.ENOENT)
    if ident.uid != entry.uid:
        _check(entry, S_IWRITE, ident)
    entry.replicas = [replica for replica in entry.replicas if replica.sfn != sfn]
    _account(conn.server, entry, -entry.size)
    return 0


def _account(server: LFCServer, entry: Entry, increment: int) -> None:
    """``fixup_parent_dirs_sz``: DPM's space accounting, which the LFC build runs too.

    The ancestors are listed from the parent up to the root, and those from
    the fourth-from-the-root back up to seven levels are adjusted - in an
    unsigned column, so a directory whose files never added to it goes
    "negative" as a huge number, exactly as the real server shows it.
    """
    chain = []
    walk = entry
    while walk.parent:
        walk = server.entries[walk.parent]
        chain.append(walk)
    depth = len(chain)
    # ``chain`` runs from the parent (index 0) up to the root (depth - 1).
    # The loop visits depth - 3 down to depth - 7, clamped at the parent:
    # at most five directories. With three or more ancestors the root and
    # the level below it are never touched; with fewer, only the parent is.
    for index in range(max(depth - 3, 0), max(depth - 7, 0) - 1, -1):
        chain[index].size = (chain[index].size + increment) % (1 << 64)


def _named(conn: _Connection, ident: Identity, reader: Unpacker, nofollow: bool = False) -> Entry:
    """A path-or-GUID lookup, as ``getreplica`` and ``getlinks`` do it.

    Reads ``HYPER cwd, STRING path, STRING guid``; the rules are
    ``statg``'s: the path when there is one (a GUID with it must match), else
    the GUID, else ``ENOENT``. ``nofollow`` is passed to the path lookup.
    """
    cwd, path, guid = reader.hyper(), _path(reader), reader.string()
    if path:
        _, entry = _parse(conn.server, ident, cwd, path, _Want(must_exist=True, nofollow=nofollow))
        if guid and guid != entry.guid:
            raise _Fail(errno.EINVAL, "GUID mismatch\n")
        return entry
    if not guid:
        raise _Fail(errno.ENOENT)
    return _by_guid(conn.server, guid)


def _h_getreplica(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_getreplica``: the file's replicas, optionally only those on one SE.

    After the :func:`_named` fields comes ``STRING se``, a host to filter by
    (empty: all). The replicas go out in one ``MSG_REPLIC``, each as
    ``HYPER fileid, HYPER nbaccesses, TIME_T atime, TIME_T ptime, BYTE
    status, BYTE f_type, STRING poolname, STRING host, STRING fs, STRING
    sfn``, and the message is left out when nothing matched. ``MSG_DATA`` with
    the ``LONG`` count always follows; the client reads that many records.
    """
    entry = _named(conn, ident, reader)
    se = reader.string()
    packer = Packer()
    count = 0
    for replica in entry.replicas:
        if se and replica.host != se:
            continue
        packer.hyper(replica.fileid).hyper(replica.nbaccesses)
        packer.hyper(replica.atime).hyper(replica.ptime)
        packer.byte(replica.status).byte(replica.f_type or "\0")
        packer.string(replica.poolname).string(replica.host).string(replica.fs)
        packer.string(replica.sfn)
        count += 1
    if count:
        conn.reply(wire.MSG_REPLIC, packer.bytes())
    conn.reply(wire.MSG_DATA, Packer().long(count).bytes())
    return 0


def _h_getlinks(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_getlinks``: the target path and every symlink to it, in ``MSG_LINKS``.

    The first string is the target - the link's own target when the lookup
    lands on a symlink, else the entry's absolute path - followed by the
    absolute path of each symlink whose stored target is exactly that
    string. Links are matched textually, so a link spelling the target
    relatively or through ``..`` is not found.
    """
    entry = _named(conn, ident, reader, nofollow=True)  # CNS_NOFOLLOW: a link names its target
    target = entry.linkname if entry.is_link() else _path_of(conn.server, entry)
    names = [target]
    for other in conn.server.entries.values():
        if other.is_link() and other.linkname == target:
            names.append(_path_of(conn.server, other))
    packer = Packer()
    for name in names:
        packer.string(name)
    conn.reply(wire.MSG_LINKS, packer.bytes())
    return 0


def _h_ping(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_ping``: ``MSG_DATA`` with the server version string (:data:`~.model.VERSION`)."""
    conn.reply(wire.MSG_DATA, Packer().string(VERSION).bytes())
    return 0


def _h_endsess(conn: _Connection, ident: Identity, magic: int, reader: Unpacker) -> int:
    """``Cns_srv_endsess``: nothing to do but succeed.

    :meth:`~.connection._Connection.session` sees the request type and ends
    the session, so this status goes out as the final ``CNS_RC``.
    """
    return 0


_HANDLERS: dict[int, Handler] = {
    wire.STAT: _h_stat,
    wire.LSTAT: _h_lstat,
    wire.STATG: _h_statg,
    wire.STATR: _h_statr,
    wire.ACCESS: _h_access,
    wire.CHMOD: _h_chmod,
    wire.MKDIR: _h_mkdir,
    wire.CREAT: _h_creat,
    wire.RMDIR: _h_rmdir,
    wire.UNLINK: _h_unlink,
    wire.DELFILES: _h_delfiles,
    wire.RENAME: _h_rename,
    wire.SYMLINK: _h_symlink,
    wire.READLINK: _h_readlink,
    wire.GETCOMMENT: _h_getcomment,
    wire.SETCOMMENT: _h_setcomment,
    wire.SETFSIZEG: _h_setfsizeg,
    wire.ADDREPLICA: _h_addreplica,
    wire.DELREPLICA: _h_delreplica,
    wire.GETREPLICA: _h_getreplica,
    wire.GETLINKS: _h_getlinks,
    wire.PING: _h_ping,
    wire.ENDSESS: _h_endsess,
}
