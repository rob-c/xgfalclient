"""The in-process LFC's corners, with hand-built requests, and the client's error paths."""

from __future__ import annotations

import errno
import socket
import stat
import struct
import time
from collections.abc import Iterator
from typing import Any

import pytest

from xgfalclient.errors import GError
from xgfalclient.plugins.lfc import csec, wire
from xgfalclient.plugins.lfc.client import CnsError, Connection, Reply, Server, _ids, socket_error
from xgfalclient.plugins.lfc.csec import GSIMechanism, IDMechanism, TokenLink
from xgfalclient.plugins.lfc.wire import Packer
from xgfalclient.testing.lfc import USER_DN, Hangup, LFCServer, Raw, _Connection, _proxy_owner
from xgfalclient.testing.pki import PKI

GUID = "12345678-1234-1234-1234-123456789abc"


@pytest.fixture
def lfc(pki: PKI) -> Iterator[LFCServer]:
    with LFCServer(gsi=pki.server_context(), mapfile={USER_DN: "xgfal"}) as server:
        server.mkdir("/grid", 0o777)
        yield server


def _server(lfc: LFCServer, mech: csec.Mechanism, sessions: bool = True) -> Server:
    return Server(lfc.host, lfc.port, lambda: [mech], sessions=sessions, timeout=10)


@pytest.fixture
def root(lfc: LFCServer) -> Iterator[Server]:
    server = _server(lfc, IDMechanism(0, 0, "root"))
    yield server
    server.close()


@pytest.fixture
def user(lfc: LFCServer, pki: PKI) -> Iterator[Server]:
    tls = pki.client_context()
    tls.check_hostname = False
    server = _server(lfc, GSIMechanism(tls))
    yield server
    server.close()


def ask(server: Server, kind: int, body: Packer | bytes, magic: int = wire.MAGIC) -> Reply:
    data = body.bytes() if isinstance(body, Packer) else body
    return server.call(magic, kind, data)


def at(path: str, cwd: int = 0) -> Packer:
    return _ids().hyper(cwd).string(path)


def status(server: Server, kind: int, body: Packer | bytes, magic: int = wire.MAGIC) -> int:
    return ask(server, kind, body, magic).status


def mine(lfc: LFCServer, path: str, **fields: object) -> None:
    lfc.add_file(path, uid=101, gid=101, **fields)  # type: ignore[arg-type]


# -- paths --------------------------------------------------------------------------------


def test_parsepath(lfc: LFCServer, root: Server) -> None:
    lfc.mkdir("/grid/d")
    lfc.add_file("/grid/d/f")
    lfc.add_link("/grid/up", "/grid/d")
    lfc.add_link("/grid/loop", "/grid/loop")
    lfc.add_link("/grid/rel", "d")
    stat_ = wire.STAT

    def st(path: str, cwd: int = 0) -> int:
        return status(
            root,
            stat_,
            at(path, cwd).hyper(0) if False else _ids().hyper(cwd).hyper(0).string(path),
        )

    assert st("/grid/./d//f") == 0
    assert st("/grid/d/../d/f") == 0
    assert st("/../grid") == 0  # .. at the root stays at the root
    assert st("/grid/d/..") == 0
    assert st("/..") == 0
    assert st("/grid/.") == 0
    assert st("/") == 0
    assert st("/grid/up/f") == 0  # a link in the middle is followed
    assert st("/grid/up") == 0
    assert st("/grid/loop") == wire.SELOOP
    assert st("/grid/loop/x") == wire.SELOOP
    assert st("/grid/rel/f") == errno.ENOENT  # relative targets resolve from cwd 0
    assert st("grid") == errno.EINVAL
    assert st("") == errno.ENOENT
    assert st("grid", cwd=2) == 0
    assert st("/grid/" + "x" * 300 + "/f") == wire.SENAMETOOLONG


def test_stat_by_fileid(lfc: LFCServer, root: Server) -> None:
    entry = lfc.add_file("/grid/f", size=4)
    reply = ask(root, wire.STAT, _ids().hyper(0).hyper(entry.fileid).string(""))
    assert reply.status == 0
    assert status(root, wire.STAT, _ids().hyper(0).hyper(999).string("")) == errno.ENOENT
    assert status(root, wire.STAT, b"\0\0") == errno.EINVAL  # does not unmarshall


def test_statg(lfc: LFCServer, root: Server) -> None:
    lfc.add_file("/grid/f", guid=GUID)
    assert status(root, wire.STATG, at("/grid/f").string(GUID)) == 0
    mismatch = ask(root, wire.STATG, at("/grid/f").string("aaaaaaaa-1234-1234-1234-123456789abc"))
    assert (mismatch.status, mismatch.errors) == (errno.EINVAL, ["GUID mismatch"])
    assert status(root, wire.STATG, at("").string("")) == errno.ENOENT
    assert status(root, wire.STATG, at("").string(GUID)) == 0
    assert status(root, wire.STATG, at("").string("00000000-0000-0000-0000-000000000000")) == (
        errno.ENOENT
    )


# -- permissions ---------------------------------------------------------------------------


def test_group_permissions(lfc: LFCServer, user: Server) -> None:
    lfc.add_file("/grid/group", mode=0o640, uid=5, gid=101)
    lfc.add_file("/grid/other", mode=0o640, uid=5, gid=7)
    assert status(user, wire.ACCESS, at("/grid/group").long(4)) == 0
    assert status(user, wire.ACCESS, at("/grid/other").long(4)) == errno.EACCES
    assert status(user, wire.ACCESS, at("/grid/group").long(0)) == 0


def test_chmod_masks(lfc: LFCServer, user: Server, root: Server) -> None:
    mine(lfc, "/grid/f")
    lfc.lookup("/grid/f").gid = 7
    assert status(user, wire.CHMOD, at("/grid/f").long(0o7777)) == 0
    assert stat.S_IMODE(lfc.lookup("/grid/f").mode) == 0o5777 & ~0o1000
    assert status(root, wire.CHMOD, at("/grid/f").long(0o7777)) == 0
    assert stat.S_IMODE(lfc.lookup("/grid/f").mode) == 0o7777
    lfc.mkdir("/grid/d", 0o755, uid=101, gid=101)
    assert status(user, wire.CHMOD, at("/grid/d").long(0o1777)) == 0
    assert stat.S_IMODE(lfc.lookup("/grid/d").mode) == 0o1777  # a directory keeps its sticky bit


def test_sticky_directory(lfc: LFCServer, user: Server) -> None:
    lfc.mkdir("/grid/tmp", 0o1777)
    lfc.add_file("/grid/tmp/theirs", uid=5, mode=0o644)
    lfc.add_file("/grid/tmp/writable", uid=5, mode=0o666)
    assert status(user, wire.UNLINK, at("/grid/tmp/theirs")) == errno.EACCES
    assert status(user, wire.UNLINK, at("/grid/tmp/writable")) == 0
    lfc.mkdir("/grid/tmp/dir", 0o755, uid=5)
    assert status(user, wire.RMDIR, at("/grid/tmp/dir")) == errno.EACCES
    mine(lfc, "/grid/tmp/own", mode=0o400)
    assert status(user, wire.UNLINK, at("/grid/tmp/own")) == 0  # the owner needs no write bit


def test_readonly(lfc: LFCServer, root: Server) -> None:
    lfc.readonly = True
    assert status(root, wire.CHMOD, at("/grid").long(0o755)) == errno.EROFS


# -- entries ---------------------------------------------------------------------------------


def mkdir_body(path: str, guid: str | None = GUID, mode: int = 0o755) -> Packer:
    body = _ids().word(0o022).hyper(0).string(path).long(mode)
    return body.string(guid) if guid is not None else body


def test_mkdir_and_creat(lfc: LFCServer, root: Server, user: Server) -> None:
    assert status(root, wire.MKDIR, mkdir_body("/"), wire.MAGIC2) == errno.EEXIST
    assert status(root, wire.MKDIR, mkdir_body("/grid/bad", "nope"), wire.MAGIC2) == errno.EINVAL
    assert status(root, wire.MKDIR, mkdir_body("/grid/old", None), wire.MAGIC) == 0
    lfc.mkdir("/grid/sgid", 0o2777, gid=55)
    assert status(user, wire.MKDIR, mkdir_body("/grid/sgid/d"), wire.MAGIC2) == 0
    created = lfc.lookup("/grid/sgid/d")
    assert (created.gid, created.mode & stat.S_ISGID) == (55, stat.S_ISGID)
    assert status(root, wire.CREAT, mkdir_body("/"), wire.MAGIC2) == errno.EISDIR
    assert status(root, wire.CREAT, mkdir_body("/grid/old"), wire.MAGIC2) == errno.EISDIR
    assert status(root, wire.CREAT, mkdir_body("/grid/new", None), wire.MAGIC) == errno.EINVAL
    reply = ask(root, wire.CREAT, mkdir_body("/grid/sgid/f", GUID, 0o644), wire.MAGIC2)
    assert reply.status == 0 and reply.reader().hyper() == lfc.lookup("/grid/sgid/f").fileid
    assert lfc.lookup("/grid/sgid/f").gid == 55
    other = "aaaaaaaa-1234-1234-1234-123456789abc"
    assert status(root, wire.CREAT, mkdir_body("/grid/sgid/f", other), wire.MAGIC2) == (
        errno.EEXIST
    )
    lfc.lookup("/grid/sgid/f").size = 9
    assert status(root, wire.CREAT, mkdir_body("/grid/sgid/f"), wire.MAGIC2) == 0
    assert lfc.lookup("/grid/sgid/f").size == 0  # re-creating truncates
    lfc.add_file("/grid/held", guid=other, replicas=("srm://se/x",))
    assert status(root, wire.CREAT, mkdir_body("/grid/held", other), wire.MAGIC2) == errno.EEXIST
    lfc.add_file("/grid/ro", guid=GUID.replace("1", "2"), mode=0o444, uid=5)
    assert status(
        user, wire.CREAT, mkdir_body("/grid/ro", GUID.replace("1", "2")), wire.MAGIC2
    ) == (errno.EACCES)


def test_rmdir_unlink_corners(lfc: LFCServer, root: Server) -> None:
    assert status(root, wire.RMDIR, at("/")) == errno.EINVAL
    assert status(root, wire.UNLINK, at("/")) == errno.EINVAL
    lfc.add_link("/grid/link", "/grid")
    assert status(root, wire.UNLINK, at("/grid/link")) == 0


def test_delfiles(lfc: LFCServer, root: Server) -> None:
    assert status(root, wire.DELFILES, _ids().word(1).word(1).hyper(0).long(0)) == errno.EINVAL
    assert status(root, wire.DELFILES, _ids().word(0).word(1).long(1).string(GUID)) == (
        errno.EINVAL
    )
    long_path = "/" + "p" * 1100
    assert root.delfiles([long_path, "/grid/none"], True) == [wire.SENAMETOOLONG, errno.ENOENT]


def test_rename_corners(lfc: LFCServer, root: Server, user: Server) -> None:
    lfc.mkdir(["/grid/a", "b"][0])
    lfc.mkdir("/grid/a/b")
    lfc.add_file("/grid/f")
    lfc.add_file("/grid/held", replicas=("srm://se/held",))
    lfc.mkdir("/grid/full")
    lfc.add_file("/grid/full/x")
    lfc.mkdir("/grid/empty")

    def rn(old: str, new: str, server: Server = root) -> int:
        return status(server, wire.RENAME, at(old).string(new))

    assert rn("/grid/f", "/grid/f") == 0
    assert rn("/", "/grid/x") == errno.EINVAL
    assert rn("/grid/f", "/") == errno.EINVAL
    assert rn("/grid/a", "/grid/a/b/c") == errno.EINVAL
    assert rn("/grid/f", "/grid/a") == errno.EISDIR
    assert rn("/grid/a", "/grid/f") == errno.ENOTDIR
    assert rn("/grid/a", "/grid/full") == errno.EEXIST
    assert rn("/grid/f", "/grid/held") == errno.EEXIST
    assert rn("/grid/a", "/grid/empty") == 0
    assert "a" not in lfc.children[lfc.lookup("/grid").fileid]
    lfc.add_file("/grid/g")
    assert rn("/grid/g", "/grid/f") == 0  # replaces
    assert rn("/grid/f", "/grid/empty/f") == 0
    lfc.mkdir("/grid/locked", 0o555, uid=5)
    lfc.mkdir("/grid/locked/in", 0o555, uid=5)
    lfc.mkdir("/grid/mine", 0o755, uid=101, gid=101)
    lfc.mkdir("/grid/mine/sealed", 0o555, uid=101, gid=101)
    assert rn("/grid/mine/sealed", "/grid/moved", user) == errno.EACCES


def test_symlink_and_readlink(lfc: LFCServer, root: Server, user: Server) -> None:
    lfc.mkdir("/grid/sgid", 0o2777, gid=55)
    assert status(user, wire.SYMLINK, at("/grid/x").string("/grid/sgid/l")) == 0
    assert lfc.lookup("/grid/sgid/l").gid == 55
    lfc.add_link("/grid/theirs", "/grid/x", uid=5)
    reply = ask(user, wire.READLINK, at("/grid/theirs"))
    assert reply.reader().string() == "/grid/x"


def test_comments(lfc: LFCServer, root: Server) -> None:
    lfc.add_file("/grid/f", comment="old")
    assert status(root, wire.SETCOMMENT, at("/grid/f").string("")) == 0
    assert lfc.lookup("/grid/f").comment is None


def test_setfsizeg(lfc: LFCServer, root: Server, user: Server) -> None:
    lfc.add_file("/grid/f", guid=GUID, uid=5, mode=0o644)
    lfc.mkdir("/grid/d")
    dir_guid = lfc.lookup("/grid/d").guid

    def sz(guid: str, size: int, kind: str, value: str, server: Server = root) -> int:
        return status(
            server, wire.SETFSIZEG, _ids().string(guid).hyper(size).string(kind).string(value)
        )

    assert sz(GUID, 1, "ADX", "") == errno.EINVAL
    assert sz(GUID, 1, "AD", "x" * 40) == errno.EINVAL
    assert sz(GUID, 1, "XX", "") == errno.EINVAL
    assert sz(GUID, -1, "", "") == errno.EINVAL
    assert sz(dir_guid, 1, "", "") == errno.EISDIR
    assert sz(GUID, 1, "MD", "abc", user) == errno.EACCES
    assert sz(GUID, 1, "MD", "abc") == 0


def replica_body(fileid: int, guid: str, host: str, sfn: str, magic: int) -> Packer:
    body = _ids().hyper(fileid).string(guid).string(host).string(sfn)
    if magic >= wire.MAGIC2:
        body.byte("-")
        if magic >= wire.MAGIC3:
            body.byte("P")
        body.string("pool")
        if magic >= wire.MAGIC3:
            body.string("fs")
    return body


def test_addreplica_variants(lfc: LFCServer, root: Server, user: Server) -> None:
    entry = lfc.add_file("/grid/f", guid=GUID)
    for index, magic in enumerate((wire.MAGIC, wire.MAGIC2, wire.MAGIC3)):
        sfn = f"srm://se/{index}"
        assert status(root, wire.ADDREPLICA, replica_body(0, GUID, "se", sfn, magic), magic) == 0
    assert [r.poolname for r in entry.replicas] == ["", "pool", "pool"]
    assert [r.fs for r in entry.replicas] == ["", "", "fs"]
    # a replica added without a file type reads back as NUL
    assert [r.f_type for r in root.getreplica(None, GUID)] == ["\0", "\0", "P"]
    add = wire.ADDREPLICA
    assert status(root, add, replica_body(0, GUID, "", "s", wire.MAGIC)) == errno.EINVAL
    assert status(root, add, replica_body(0, GUID, "se", "", wire.MAGIC)) == errno.EINVAL
    assert status(root, add, replica_body(999, "", "se", "s", wire.MAGIC)) == errno.ENOENT
    assert status(root, add, replica_body(0, "", "se", "s", wire.MAGIC)) == errno.ENOENT
    assert status(root, add, replica_body(entry.fileid, "", "se", "s2", wire.MAGIC)) == 0
    lfc.mkdir("/grid/d")
    dir_id = lfc.lookup("/grid/d").fileid
    assert status(root, add, replica_body(dir_id, "", "se", "s3", wire.MAGIC)) == errno.EISDIR
    lfc.add_file("/grid/private", mode=0o600, uid=5)
    private = lfc.lookup("/grid/private").fileid
    assert status(user, add, replica_body(private, "", "se", "s4", wire.MAGIC)) == errno.EACCES


def test_delreplica_variants(lfc: LFCServer, root: Server, user: Server) -> None:
    entry = lfc.add_file("/grid/f", guid=GUID, replicas=("srm://se/a", "srm://se/b", "srm://se/c"))
    other = lfc.add_file("/grid/g")

    def dr(fileid: int, guid: str, sfn: str, server: Server = root) -> int:
        return status(server, wire.DELREPLICA, _ids().hyper(fileid).string(guid).string(sfn))

    assert dr(999, "", "srm://se/a") == errno.ENOENT
    assert dr(other.fileid, "", "srm://se/a") == errno.ENOENT
    assert dr(0, GUID, "srm://se/a") == 0
    assert dr(0, "", "srm://se/b") == 0
    assert dr(entry.fileid, "", "srm://se/c", user) == errno.EACCES


def test_getreplica_filters(lfc: LFCServer, root: Server) -> None:
    lfc.add_file("/grid/f", guid=GUID, replicas=("srm://se1/a", "srm://se2/b"))
    assert [r.sfn for r in root.getreplica("/grid/f", se="se2")] == ["srm://se2/b"]
    assert [r.sfn for r in root.getreplica(None, GUID)] == ["srm://se1/a", "srm://se2/b"]
    assert len(root.getreplica("/grid/f", GUID)) == 2  # a path and its own GUID agree
    mismatch = ask(root, wire.GETREPLICA, at("/grid/f").string("x").string(""))
    assert mismatch.status == errno.EINVAL
    assert status(root, wire.GETREPLICA, at("").string("").string("")) == errno.ENOENT


# -- listings ---------------------------------------------------------------------------------


def test_listing_by_guid_and_readdirg(lfc: LFCServer, root: Server) -> None:
    lfc.mkdir("/grid/d")
    lfc.add_file("/grid/d/f", csumtype="AD", csumvalue="01020304")
    guid = lfc.lookup("/grid/d").guid

    def exchange(conn: Connection) -> Reply:
        opened = conn.call(wire.MAGIC2, wire.OPENDIR, at("").string(guid).bytes())
        fileid = opened.reader().hyper()
        batch = conn.call(
            wire.MAGIC2, wire.READDIR, _ids().word(1).word(138).hyper(fileid).word(1).bytes()
        )
        reader = batch.reader()
        assert reader.word() == 1
        reader.hyper()
        assert reader.string() == lfc.lookup("/grid/d/f").guid
        conn.call(wire.MAGIC, wire.CLOSEDIR)
        return batch

    root.run(exchange)


def test_listing_refusals(lfc: LFCServer, root: Server, pki: PKI) -> None:
    def opendir(path: str, readdir_attr: int = 1) -> list[int]:
        found: list[int] = []

        def exchange(conn: Connection) -> Reply:
            opened = conn.call(wire.MAGIC, wire.OPENDIR, at(path).string("").bytes())
            found.append(opened.status)
            if opened.status:
                return opened
            fileid = opened.reader().hyper()
            body = _ids().word(readdir_attr).word(62).hyper(fileid).word(1).bytes()
            batch = conn.call(wire.MAGIC, wire.READDIR, body)
            found.append(batch.status)
            return batch

        root.run(exchange)
        return found

    assert opendir("/grid", 0) == [0, wire.SEOPNOTSUP]
    lfc.inject(wire.READDIR, errno.EIO)
    assert opendir("/grid") == [0, errno.EIO]
    lfc.mkdir("/grid/closed", 0o700, uid=5)
    tls = pki.client_context()
    tls.check_hostname = False
    unmapped = LFCServer(gsi=pki.server_context(), mapfile={})
    with unmapped:
        server = _server(unmapped, GSIMechanism(tls))
        reply = server.call(wire.MAGIC, wire.OPENDIR, at("/").string("").bytes())
        assert reply.status == wire.SENOMAPFND
        assert reply.errors[0].startswith("Could not get virtual id")
        server.close()


def test_listing_abandoned(lfc: LFCServer, root: Server) -> None:
    """A client that goes away mid-listing: the server's thread ends."""

    def exchange(conn: Connection) -> Reply:
        opened = conn.call(wire.MAGIC, wire.OPENDIR, at("/grid").string("").bytes())
        conn.close()
        return opened

    root.run(exchange)
    time.sleep(0.1)
    assert status(root, wire.PING, _ids()) == 0


def test_listing_other_request_ends_it(lfc: LFCServer, root: Server) -> None:
    def exchange(conn: Connection) -> Reply:
        conn.call(wire.MAGIC, wire.OPENDIR, at("/grid").string("").bytes())
        return conn.call(wire.MAGIC, wire.STATG, at("/grid").string("").bytes())

    assert root.run(exchange).status == 0  # swallowed as the end of the listing


# -- connections and Csec, server side ------------------------------------------------------------


def raw_connect(lfc: LFCServer) -> socket.socket:
    return socket.create_connection((lfc.host, lfc.port), timeout=5)


def test_bad_first_token(lfc: LFCServer) -> None:
    with raw_connect(lfc) as sock:
        TokenLink(sock, "s").send_token(csec.HANDSHAKE, b"x")
        assert sock.recv(10) == b""
    with raw_connect(lfc) as sock:
        sock.sendall(b"\0" * 12)
        assert sock.recv(10) == b""


def test_id_token_malformed(lfc: LFCServer) -> None:
    with raw_connect(lfc) as sock:
        link = TokenLink(sock, "s")
        csec.negotiate(link, ["ID"])
        link.send_token(csec.HANDSHAKE, b"only two")
        assert sock.recv(10) == b""
    with raw_connect(lfc) as sock:
        link = TokenLink(sock, "s")
        csec.negotiate(link, ["ID"])
        link.send_token(csec.HANDSHAKE_FINAL, b"0 0 root")  # the wrong token type
        assert sock.recv(10) == b""


def test_first_shared_mechanism_is_chosen(lfc: LFCServer) -> None:
    with raw_connect(lfc) as sock:
        assert csec.negotiate(TokenLink(sock, "s"), ["KRB5", "ID"]) == "ID"


def test_bad_request_headers(lfc: LFCServer) -> None:
    """A length shorter than a header, or a body that never comes: the server hangs up."""
    for length, rest in ((4, b""), (wire.HEADER.size + 8, b"shor")):
        with raw_connect(lfc) as sock:
            csec.authenticate(sock, "s", lfc.host, [IDMechanism(0, 0, "root")])
            sock.sendall(wire.HEADER.pack(wire.MAGIC, wire.PING, length) + rest)
            sock.shutdown(socket.SHUT_WR)
            assert sock.recv(10) == b""


def test_id_with_authorization(lfc: LFCServer) -> None:
    with raw_connect(lfc) as sock:
        csec.authenticate(sock, "s", lfc.host, [IDMechanism(0, 0, "root")], ("GSI", USER_DN))
        conn = Connection(sock, "s")
        reply = conn.call(wire.MAGIC, wire.MKDIR, mkdir_body("/grid/byproxy").bytes())
        assert reply.status == 0
    assert lfc.lookup("/grid/byproxy").uid == 101


def test_gsi_refused_without_server_credential(lfc: LFCServer, pki: PKI) -> None:
    tls = pki.client_context()
    tls.check_hostname = False
    with LFCServer(mechanisms=("GSI",)) as plain:
        server = _server(plain, GSIMechanism(tls))
        with pytest.raises(GError):
            server.ping()


def test_gsi_client_aborts(lfc: LFCServer) -> None:
    with raw_connect(lfc) as sock:
        link = TokenLink(sock, "s")
        csec.negotiate(link, ["GSI"])
        link.send_token(csec.HANDSHAKE_ERROR, struct.pack(">I", 1))
        _, _, value = wire.HEADER.unpack(sock.recv(12))
        assert value == wire.ESEC_NO_CONTEXT


def test_gsi_garbage(lfc: LFCServer) -> None:
    with raw_connect(lfc) as sock:
        link = TokenLink(sock, "s")
        csec.negotiate(link, ["GSI"])
        link.send_token(csec.HANDSHAKE, b"\x16\x03\x01\x00\x05hello")
        kind, _ = link.recv_token()
        assert kind == csec.HANDSHAKE_ERROR


def test_gsi_error_token_lost(lfc: LFCServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """The server cannot even report the failure: it still closes cleanly."""
    from xgfalclient.testing import lfc as fake

    real = fake.TokenLink.send_token

    def fragile(self: TokenLink, kind: int, data: bytes) -> None:
        if kind == csec.HANDSHAKE_ERROR:
            raise GError("gone", errno.EPIPE)
        real(self, kind, data)

    monkeypatch.setattr(fake.TokenLink, "send_token", fragile)
    with raw_connect(lfc) as sock:
        link = TokenLink(sock, "s")
        csec.negotiate(link, ["GSI"])
        link.send_token(csec.HANDSHAKE, b"junk" * 4)
        assert wire.HEADER.unpack(sock.recv(12))[2] == wire.ESEC_NO_CONTEXT


def test_no_request_after_auth(lfc: LFCServer, root: Server) -> None:
    conn = root.connect()
    conn.close()
    with raw_connect(lfc) as sock:
        csec.authenticate(sock, "s", lfc.host, [IDMechanism(0, 0, "root")])
    time.sleep(0.05)


def test_plain_requests(lfc: LFCServer) -> None:
    server = _server(lfc, IDMechanism(0, 0, "root"), sessions=False)
    assert server.ping() == "1.13.0-1"
    unknown = server.call(wire.MAGIC, 99, _ids().bytes())
    assert (unknown.status, unknown.errors, unknown.final) == (
        wire.SEOPNOTSUP,
        ["NS003 - illegal function 99"],
        True,
    )
    empty = server.call(wire.MAGIC, wire.STAT)
    assert empty.status == wire.SEINTERNAL
    assert server.call(wire.MAGIC, wire.CLOSEDIR).status == wire.SEINTERNAL


def test_session_request_with_empty_body(lfc: LFCServer, root: Server) -> None:
    assert root.call(wire.MAGIC, wire.STAT).status == wire.SEINTERNAL
    assert status(root, wire.PING, _ids()) == 0  # the session goes on


def test_session_hangup_injection(lfc: LFCServer, root: Server) -> None:
    root.ping()
    lfc.inject(wire.PING, Hangup(), Hangup())
    with pytest.raises(GError) as info:
        root.ping()  # twice: the retry lands on a fresh connection, hung up too
    assert info.value.code == errno.ECONNRESET


def test_raw_injection_and_oversized_reply(lfc: LFCServer, root: Server) -> None:
    lfc.inject(wire.PING, Raw(wire.HEADER.pack(wire.MAGIC2, wire.MSG_DATA, 999999)))
    with pytest.raises(GError, match="reply of 999999 bytes") as info:
        root.ping()
    assert info.value.code == errno.EPROTO


def test_injected_status(lfc: LFCServer, root: Server) -> None:
    lfc.inject(wire.STATG, errno.EIO)
    with pytest.raises(CnsError) as info:
        root.statg("/grid")
    assert (info.value.code, info.value.serrno) == (errno.EIO, errno.EIO)


# -- client error paths ---------------------------------------------------------


def test_request_on_closed_socket(root: Server) -> None:
    conn = root.connect()
    conn.sock.close()
    with pytest.raises(GError):
        conn.send(b"x")
    assert conn.closed


def test_reply_timeout(lfc: LFCServer) -> None:
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def silent() -> None:
        sock, _ = listener.accept()
        link = TokenLink(sock, "c")
        link.recv_token()
        link.send_token(csec.PROTOCOL_RESP, csec.encode_response(2, 0, csec.NODELEG, []))
        link.recv_token()
        time.sleep(1)
        sock.close()

    import threading

    thread = threading.Thread(target=silent, daemon=True)
    thread.start()
    server = Server("127.0.0.1", port, lambda: [IDMechanism(0, 0, "r")], timeout=0.2)
    with pytest.raises(GError) as info:
        server.ping()
    assert info.value.code == errno.ETIMEDOUT
    thread.join(5)
    listener.close()


def test_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(self: socket.socket, address: object) -> None:
        raise socket.timeout("timed out")

    monkeypatch.setattr(socket.socket, "connect", slow)
    server = Server("127.0.0.1", 1, lambda: [], retries=0)
    with pytest.raises(GError) as info:
        server.ping()
    assert info.value.code == errno.ETIMEDOUT


def test_socket_error_without_errno() -> None:
    error = socket_error(OSError("gone"), "Lost the LFC")
    assert (error.code, error.message) == (errno.ECONNRESET, "Lost the LFC: gone")


def test_failure_after_a_reply_is_not_retried(lfc: LFCServer, root: Server) -> None:
    """A pooled connection that already answered was not dead: no second try."""
    root.ping()
    lfc.inject(wire.STATG, Hangup())

    def exchange(conn: Connection) -> Reply:
        conn.call(wire.MAGIC, wire.PING, _ids().bytes())
        return conn.call(wire.MAGIC, wire.STATG, at("/grid").string("").bytes())

    with pytest.raises(GError) as info:
        root.run(exchange)
    assert info.value.code == errno.ECONNRESET
    assert lfc.connections == 1


def test_timeout_on_a_pooled_connection_is_not_retried(
    lfc: LFCServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    from xgfalclient.testing import lfc as fake

    server = Server(lfc.host, lfc.port, lambda: [IDMechanism(0, 0, "root")], timeout=0.2)
    server.ping()

    def slow(*args: object) -> int:
        time.sleep(0.5)
        return 0

    monkeypatch.setitem(fake._HANDLERS, wire.PING, slow)
    with pytest.raises(GError) as info:
        server.ping()
    assert info.value.code == errno.ETIMEDOUT
    assert lfc.connections == 1
    server.close()


def test_failed_exchange_is_not_retried_on_fresh(lfc: LFCServer, root: Server) -> None:
    def broken(conn: Connection) -> Reply:
        raise KeyError("bug")

    with pytest.raises(KeyError):
        root.run(broken)


def test_pool_limits(lfc: LFCServer, root: Server) -> None:
    from xgfalclient.plugins.lfc import client

    conns = [root.connect() for _ in range(client.MAX_POOL + 1)]
    for conn in conns:
        root.release(conn)
    assert len(root._idle) == client.MAX_POOL
    root.close()
    time.sleep(0.05)
    assert lfc.log.count((wire.ENDSESS, wire.MAGIC)) == client.MAX_POOL + 1


def test_endsess_on_dead_connection(root: Server) -> None:
    conn = root.connect()
    conn.sock.close()
    root._end(conn)  # nothing raised


def test_stale_by_age(root: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    from xgfalclient.plugins.lfc import client

    conn = root.connect()
    assert not conn.stale()
    monkeypatch.setattr(client, "MAX_IDLE_SECONDS", -1.0)
    assert conn.stale()
    conn.close()
    assert conn.stale()


def test_listing_error_mid_way(lfc: LFCServer, root: Server) -> None:
    lfc.inject(wire.READDIR, errno.EIO)
    with pytest.raises(CnsError) as info:
        root.listdir("/grid")
    assert info.value.code == errno.EIO


def test_listing_without_sessions(lfc: LFCServer) -> None:
    lfc.mkdir("/grid/d")
    server = _server(lfc, IDMechanism(0, 0, "root"), sessions=False)
    assert [entry.name for entry in server.listdir("/grid")] == ["d"]
    with pytest.raises(CnsError):
        server.listdir("/nothing")


def test_listing_ended_by_the_server(lfc: LFCServer) -> None:
    """A server that ends the connection with success mid-listing: what came so far."""
    lfc.mkdir("/grid/d")
    server = _server(lfc, IDMechanism(0, 0, "root"), sessions=False)
    lfc.inject(wire.OPENDIR, 0)
    assert server.listdir("/grid") == []
    lfc.inject(wire.READDIR, 0)
    assert server.listdir("/grid") == []


def test_empty_directory(lfc: LFCServer, root: Server) -> None:
    lfc.mkdir("/grid/empty")
    assert root.listdir("/grid/empty") == []


def test_proxy_owner() -> None:
    assert _proxy_owner("/DC=org/CN=Jo/CN=123/CN=proxy") == "/DC=org/CN=Jo"
    assert _proxy_owner("/DC=org/CN=Jo/CN=limited proxy") == "/DC=org/CN=Jo"
    assert _proxy_owner("/CN=42") == "/CN=42"
    assert _proxy_owner("/DC=org/OU=People") == "/DC=org/OU=People"


def test_lookup_and_url(lfc: LFCServer) -> None:
    assert lfc.url("/x") == f"lfc://localhost:{lfc.port}/x"
    with pytest.raises(KeyError):
        lfc.lookup("/nope")


def test_ipv6_listener(pki: PKI) -> None:
    try:
        server = LFCServer(host="::1")
    except OSError:  # pragma: no cover - a host without IPv6 loopback
        pytest.skip("no IPv6 loopback")
    with server:
        client = Server("::1", server.port, lambda: [IDMechanism(0, 0, "root")])
        assert client.ping() == "1.13.0-1"
        client.close()


def test_delreplica_space_accounting(lfc: LFCServer, root: Server) -> None:
    """As the real server does: parents lose the size, in an unsigned column."""
    lfc.mkdir("/grid/a")
    lfc.mkdir("/grid/a/b")
    lfc.add_file("/grid/a/b/f", size=10, replicas=("srm://se/f",))
    lfc.add_file("/top", size=3, replicas=("srm://se/top",))
    root.delreplica(None, 0, "srm://se/f")
    root.delreplica(None, 0, "srm://se/top")
    sizes = [lfc.lookup(path).size for path in ("/grid/a/b", "/grid/a", "/grid", "/")]
    assert sizes == [2**64 - 10, 2**64 - 10, 0, 2**64 - 3]
    assert root.stat("/grid/a").size == 2**64 - 10


def test_delegation_is_refused(lfc: LFCServer) -> None:
    """A client that insists on delegation shares no protocol with the LFC."""
    request = Packer().long(2).long(0).long(1).string("GSI")
    request.long(1).long(csec.DELEG).long(1).long(0).long(0)
    with raw_connect(lfc) as sock:
        link = TokenLink(sock, "s")
        link.send_token(csec.PROTOCOL_REQ, request.bytes())
        kind, data = link.recv_token()
        assert kind == csec.PROTOCOL_RESP
        assert csec.decode_response(data)[1] is None


def test_unterminated_path(lfc: LFCServer, root: Server) -> None:
    assert status(root, wire.STAT, _ids().hyper(0).hyper(0).raw(b"/grid")) == errno.EINVAL


def test_connection_close_ignores_a_failing_socket() -> None:
    class Unclosable:
        def close(self) -> None:
            raise OSError(errno.EBADF, "already gone")

    sock: Any = Unclosable()
    _Connection(None, sock, "peer").close()  # type: ignore[arg-type]
