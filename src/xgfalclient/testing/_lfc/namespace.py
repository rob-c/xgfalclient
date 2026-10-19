"""The catalogue's rules, shared by every request handler (``Cns_parsepath`` and friends).

Path resolution (symlinks, ``..``, search permission on each component,
write permission on the parent), the permission check without ACLs,
GUID lookups, ancestors' search permission, removal and the sticky bit,
and the marshalling of ``stat``/``statg``/``DIRX`` records and of the
length-checked path strings requests carry. Callers hold the server's lock.

Everything here raises :class:`~.model._Fail` with the serrno the real
server returns, so a handler can let it propagate to
:meth:`~.connection._Connection.process`, which turns it into the request's
status. The record marshallers write the columns in the order
``Cns_procreq.c`` marshalls them; the client's unmarshallers in
:mod:`xgfalclient.plugins.lfc.client` read the same order, and a mismatch
shows up as garbage in every later field rather than as an error, so keep
them in step field for field.
"""

from __future__ import annotations

import errno
import stat as _stat
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...plugins.lfc import wire
from ...plugins.lfc.wire import Packer, Unpacker
from .model import S_IEXEC, S_IWRITE, Entry, Identity, _Fail

if TYPE_CHECKING:
    from ..lfc import LFCServer
    from .connection import _Connection


@dataclass(frozen=True, slots=True)
class _Want:
    """What a caller of :func:`_parse` needs from the last path component.

    ``must_exist`` turns a missing last component into ``ENOENT``; without
    it the component comes back as a placeholder :class:`Entry` with
    ``fileid`` 0, which is how ``creat``/``mkdir``/``symlink``/``rename``
    learn the name they are about to make. ``nofollow`` stops a symlink in
    the last place from being followed (``lstat``, ``readlink``, ``unlink``:
    they act on the link). ``parent`` also returns the containing directory,
    after checking write and search permission on it, as every request
    that adds or removes a name must.
    """

    must_exist: bool = False
    nofollow: bool = False
    parent: bool = False


#: The common case: an existing entry, symlinks followed, no parent wanted.
_EXISTING = _Want(must_exist=True)
#: The link itself, which must exist (``lstat``-like lookups, ``readlink``).
_EXISTING_LINK = _Want(must_exist=True, nofollow=True)
#: An existing name to remove or move away, with its writable parent.
_REMOVABLE = _Want(must_exist=True, nofollow=True, parent=True)
#: A name to create or replace, with its writable parent; it may not exist yet.
_NEW_NAME = _Want(nofollow=True, parent=True)


def _check(entry: Entry, mode: int, ident: Identity) -> None:
    """``Cns_chkentryperm`` without ACLs; uid 0 stands for Cupv's administrators.

    ``mode`` is given in owner bits (:data:`~.model.S_IREAD`...). For anyone
    but the owner it is shifted to the group triplet, and again to "other"
    when the entry's gid is not one of the caller's - classic Unix, where
    the first matching class decides even if a later one would grant more.
    Failure is ``EACCES``.
    """
    if ident.uid == 0:
        return
    if entry.uid != ident.uid:
        mode >>= 3
        if entry.gid not in ident.gids:
            mode >>= 3
    if entry.mode & mode != mode:
        raise _Fail(errno.EACCES)


def _by_guid(server: LFCServer, guid: str) -> Entry:
    """The entry with ``guid`` (``Cns_get_fmd_by_guid``), else ``ENOENT``.

    A linear scan: the test catalogues hold tens of entries, and keeping no
    index means nothing can go stale when a handler rewrites a row. Unlike
    path lookups no ancestor is checked here; handlers that need the search
    permission real GUID requests imply call :func:`_chkback` themselves.
    """
    for entry in server.entries.values():
        if entry.guid == guid:
            return entry
    raise _Fail(errno.ENOENT)


def _get(server: LFCServer, parent: int, name: str) -> Entry:
    """The entry called ``name`` in directory ``parent``, else ``ENOENT``.

    ``parent`` 0 is the pseudo-directory above the root, whose only child is
    ``"/"``; that is how an absolute path's first piece resolves.
    """
    fileid = server.children.get(parent, {}).get(name)
    if fileid is None:
        raise _Fail(errno.ENOENT)
    return server.entries[fileid]


def _parse(
    server: LFCServer, ident: Identity, cwd: int, path: str, want: _Want
) -> tuple[Entry | None, Entry]:
    """``Cns_parsepath``: ``(parent, entry)``; a new name comes back with ``fileid`` 0.

    ``cwd`` is the file id a relative ``path`` starts from (requests carry
    it; liblfc always sends 0 and absolute paths, so a relative path with no
    ``cwd`` is ``EINVAL``). Every directory walked through needs search
    permission (``EACCES``), must be a directory (``ENOTDIR``) and have a
    name of at most ``MAXNAMELEN`` (255) bytes (``SENAMETOOLONG``). A symlink
    met on the way is replaced by its target and the walk restarts from the
    top of the new path, as the C code does; more than ``MAXSYMLINKS`` of
    them in one lookup is ``SELOOP``. ``..`` at the root stays at the root.
    ``want`` says how to treat the last component (see :class:`_Want`);
    ``parent`` in the result is ``None`` unless ``want.parent`` is set, and
    also for the root, which has none.
    """
    if not path:
        raise _Fail(errno.ENOENT)
    if not cwd and not path.startswith("/"):
        raise _Fail(errno.EINVAL)
    links = 0
    while True:
        path = path.rstrip("/") or "/"
        # ``current`` None stands for the pseudo-directory above the root;
        # an absolute path's leading "/" is looked up in it like a name.
        current = server.entries.get(cwd) if cwd else None
        walk, component = _split(path)
        current, target = _walk(server, ident, current, walk, component)
        if target is None:
            entry, target = _last(server, current, component, want)
            if target is None:
                return _with_parent(server, entry, want, ident), entry
        # A symlink: start again from the top of the path it makes.
        links = _count_link(links)
        path = target


def _split(path: str) -> tuple[list[str], str]:
    """The directories to walk through and the last component of a stripped ``path``.

    An absolute path's first piece is ``"/"``, the root's name in the
    pseudo-directory above it; ``"/"`` alone is that name and nothing to walk.
    """
    if path == "/":
        return [], path
    pieces = path.split("/")
    if path.startswith("/"):
        pieces[0] = "/"
    *walk, component = pieces
    return walk, component


def _count_link(links: int) -> int:
    """One more symlink followed in this lookup; more than ``MAXSYMLINKS`` is ``SELOOP``."""
    links += 1
    if links > wire.MAXSYMLINKS:
        raise _Fail(wire.SELOOP)
    return links


def _walk(
    server: LFCServer, ident: Identity, current: Entry | None, walk: list[str], component: str
) -> tuple[Entry | None, str | None]:
    """Walk ``walk`` from ``current``: ``(directory reached, None)`` or ``(link, new path)``.

    Each directory passed through needs search permission. A symlink met on
    the way ends the walk with the path to restart from: its target spliced
    in front of the rest of the walk, so a relative target resolves against
    ``cwd``, not against the link's own directory, as the C code does.
    """
    for index, piece in enumerate(walk):
        if piece in ("", "."):
            continue
        if piece == "..":
            current = _up(server, current)
            continue
        if len(piece) > wire.MAXNAMELEN:
            raise _Fail(wire.SENAMETOOLONG)
        current = _get(server, current.fileid if current else 0, piece)
        if current.is_link():
            return current, "/".join([current.linkname, *walk[index + 1 :], component])
        if not current.is_dir():
            raise _Fail(errno.ENOTDIR)
        _check(current, S_IEXEC, ident)
    return current, None


def _up(server: LFCServer, current: Entry | None) -> Entry:
    """``..`` from ``current``: its parent, or ``current`` itself at the root."""
    assert current is not None
    return server.entries[current.parent] if current.parent else current


def _last(
    server: LFCServer, current: Entry | None, component: str, want: _Want
) -> tuple[Entry, str | None]:
    """The entry the last ``component`` names in ``current``, as ``want`` says.

    ``(entry, None)``, or ``(link, its target)`` for a symlink to follow.
    A missing name is a placeholder :class:`Entry` with ``fileid`` 0 unless
    ``want.must_exist``. The component is never empty: the path was
    stripped of trailing "/".
    """
    if component == "..":
        return _up(server, current), None
    if component == ".":
        assert current is not None
        return current, None
    if len(component) > wire.MAXNAMELEN:
        raise _Fail(wire.SENAMETOOLONG)
    base = current.fileid if current else 0
    try:
        entry = _get(server, base, component)
    except _Fail:
        if want.must_exist:
            raise
        return Entry(0, base, component, 0), None
    if entry.is_link() and not want.nofollow:
        return entry, entry.linkname
    return entry, None


def _with_parent(server: LFCServer, entry: Entry, want: _Want, ident: Identity) -> Entry | None:
    """``entry``'s directory, checked writable and searchable, when ``want.parent`` asks for it.

    ``None`` when it does not, and for the root, which has no parent.
    """
    if want.parent and entry.parent:
        above = server.entries[entry.parent]
        _check(above, S_IEXEC | S_IWRITE, ident)
        return above
    return None


def _path_of(server: LFCServer, entry: Entry) -> str:
    """``getpath``: an entry's absolute path from the root down."""
    parts = []
    while entry.fileid != 2:
        parts.append(entry.name)
        entry = server.entries[entry.parent]
    return "/" + "/".join(reversed(parts))


def _chkback(server: LFCServer, fileid: int, ident: Identity) -> None:
    """``Cns_chkbackperm``: search permission on every ancestor."""
    while fileid > 2:
        entry = server.entries[fileid]
        _check(entry, S_IEXEC, ident)
        fileid = entry.parent


def _stat_record(packer: Packer, entry: Entry) -> None:
    """A ``Cns_filestat`` as ``Cns_srv_stat`` sends it.

    ``HYPER fileid, WORD mode, LONG nlink, LONG uid, LONG gid, HYPER size,
    TIME_T atime, mtime, ctime, WORD fileclass, BYTE status``.
    """
    packer.hyper(entry.fileid).word(entry.mode).long(entry.nlink).long(entry.uid).long(entry.gid)
    packer.hyper(entry.size).hyper(entry.atime).hyper(entry.mtime).hyper(entry.ctime)
    packer.word(entry.fileclass).byte(entry.status)


def _statg_record(packer: Packer, entry: Entry) -> None:
    """A ``Cns_filestatg``: the stat record with the GUID after the file id
    and the checksum type and value at the end (``statg``, ``statr``).
    """
    packer.hyper(entry.fileid).string(entry.guid).word(entry.mode).long(entry.nlink)
    packer.long(entry.uid).long(entry.gid).hyper(entry.size)
    packer.hyper(entry.atime).hyper(entry.mtime).hyper(entry.ctime)
    packer.word(entry.fileclass).byte(entry.status).string(entry.csumtype)
    packer.string(entry.csumvalue)


def _dirx(packer: Packer, magic: int, entry: Entry) -> None:
    """``marshall_DIRX``: one ``readdir`` record, the stat columns then the name.

    Under ``CNS_MAGIC2`` and later the record is the ``Cns_direnstatg``
    form, with the GUID and checksum columns of :func:`_statg_record`;
    the older magic gets the plain ``Cns_direnstat``. liblfc lists with
    ``CNS_MAGIC``, so the client reads the plain form.
    """
    packer.hyper(entry.fileid)
    if magic >= wire.MAGIC2:
        packer.string(entry.guid)
    packer.word(entry.mode).long(entry.nlink).long(entry.uid).long(entry.gid)
    packer.hyper(entry.size).hyper(entry.atime).hyper(entry.mtime).hyper(entry.ctime)
    packer.word(entry.fileclass).byte(entry.status)
    if magic >= wire.MAGIC2:
        packer.string(entry.csumtype).string(entry.csumvalue)
    packer.string(entry.name)


def _nstring(reader: Unpacker, size: int) -> tuple[str, bool]:
    """``_unmarshall_NSTRINGN``: the string, cut to ``size - 1``, and whether it fit.

    An over-long string is still consumed up to its NUL, so the fields after
    it stay in step; a string with no NUL at all consumes the rest.
    """
    data = reader.data
    end = data.find(b"\0", reader.pos)
    if end < 0:
        reader.pos = len(data)
        return "", False
    raw = data[reader.pos : end]
    reader.pos = end + 1
    fits = len(raw) < size
    return raw[: size - 1].decode("utf-8", "surrogateescape"), fits


def _path(reader: Unpacker) -> str:
    """A path field: ``SENAMETOOLONG`` over 1023 bytes, ``EINVAL`` if unterminated."""
    text, fits = _nstring(reader, wire.MAXPATHLEN + 1)
    if not fits:
        raise _Fail(wire.SENAMETOOLONG if text else errno.EINVAL)
    return text


def _writable(conn: _Connection) -> None:
    """``EROFS`` when :attr:`LFCServer.readonly` is set; changing requests call it first."""
    if conn.server.readonly:
        raise _Fail(errno.EROFS)


def _remove(server: LFCServer, parent: Entry, entry: Entry) -> None:
    """Delete ``entry`` from ``parent``, with its child table and replicas.

    Permission and emptiness checks are the caller's; this only keeps the
    catalogue consistent - the parent's ``nlink`` and its ``mtime``/``ctime``
    change, as a directory's do when a name goes.
    """
    del server.entries[entry.fileid]
    del server.children[parent.fileid][entry.name]
    server.children.pop(entry.fileid, None)
    parent.nlink -= 1
    parent.mtime = parent.ctime = int(time.time())


def _sticky(parent: Entry, entry: Entry, ident: Identity) -> None:
    """The sticky-bit rule for removing ``entry`` from ``parent``.

    In an ``S_ISVTX`` directory only the directory's owner, the entry's
    owner, or someone with write permission on the entry itself may remove
    or rename it (``EACCES`` otherwise); root passes through :func:`_check`.
    """
    if parent.mode & _stat.S_ISVTX and ident.uid not in (parent.uid, entry.uid):
        _check(entry, S_IWRITE, ident)
