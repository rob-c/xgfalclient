"""The test GridFTP server's login and session-setting verbs.

``AUTH``/``ADAT`` (RFC 2228 GSI, with delegation), ``USER``/``PASS`` against
the server's user table or grid-map, ``FEAT``, ``QUIT``, and the verbs that
only change session state: ``TYPE``, ``MODE``, ``DCAU``, ``PROT``, ``OPTS``,
``SITE``, ``REST`` and their no-op companions. Nothing here touches a data
channel; that is :mod:`.data`.

The reply wording follows globus-gridftp-server 13 where a client parses
it (``334``/``335``/``235`` with ``ADAT=``, ``331``, ``230``, the ``211``
``FEAT`` block); elsewhere a plausible RFC 959 reply is enough.
"""

from __future__ import annotations

import base64
import os
import shutil
import tempfile

from xrdsec.gsi.gss import GSIError

from ...plugins.gridftp.gsi import GlobusContext
from .base import _SessionBase
from .common import _Hangup, _Reply


class _Commands(_SessionBase):
    """Login and session-setting verbs."""

    # -- login ----------------------------------------------------------------------------

    def do_AUTH(self, arg: str) -> None:
        """``AUTH GSSAPI``: start a GSI handshake (RFC 2228 ``334``).

        Only a ``gsiftp://`` server (one given a TLS context) accepts it,
        and only the ``GSSAPI`` mechanism; anything else is ``504``. A new
        ``AUTH`` discards a half-finished handshake.
        """
        if self.server.gsi is None or arg.upper() != "GSSAPI":
            raise _Reply("504 Authentication type not supported.")
        self.adat = GlobusContext(
            self.server.gsi,
            server_side=True,
            delegation_key=self.server.delegation_key,
            turn=self.server.globus_turn,
        )
        raise _Reply("334 Using authentication type; ADAT must follow.")

    def do_ADAT(self, arg: str) -> None:
        """``ADAT <base64>``: one step of the GSI handshake, then delegation.

        Each token is a TLS record (or several) fed to the server-side
        :class:`~xgfalclient.plugins.gridftp.gsi.GlobusContext`. While the
        handshake is incomplete the answer is RFC 2228's ``335 ADAT=<reply
        token>``; once complete it is ``235`` (with a final token if TLS
        has one to send), and from then on the control channel is protected.
        A bad token is ``535`` and resets the handshake. The client's DN,
        with trailing proxy CNs (numeric, or ``proxy``/``limited proxy``)
        removed, becomes :attr:`identity` for the grid-map and ``DCAU A``.
        A delegated proxy is written to a private temporary file for the
        session's data channels.
        """
        context = self.adat
        if context is None:
            raise _Reply("503 You must issue the AUTH command prior to ADAT.")
        try:
            token = context.step(base64.b64decode(arg))
        except (GSIError, ValueError):
            self.adat = None
            raise _Reply("535 GSSAPI authentication failed.") from None
        encoded = base64.b64encode(token).decode("ascii")
        if not context.complete:
            raise _Reply(f"335 ADAT={encoded}")
        # Without a client certificate (a context built with
        # ``require_client=False``) the peer is anonymous.
        peer = context.peer_certificate()
        rdns = peer.subject.rdns if peer is not None else ()
        while (
            rdns
            and rdns[-1][0] == "CN"
            and (rdns[-1][1].isdigit() or rdns[-1][1].endswith("proxy"))
        ):
            rdns = rdns[:-1]
        self.identity = rdns
        if context.delegated is not None:
            handle, self.delegated = tempfile.mkstemp(prefix="xgfal-delegated-")
            with os.fdopen(handle, "wb") as out:
                out.write(context.delegated.pem())
        # The 235 must go out in clear: protection starts with the next reply,
        # so ``security`` is set only after it is sent.
        self.reply(f"235 ADAT={encoded}" if token else "235 GSSAPI Authentication successful.")
        self.security = context

    def do_USER(self, arg: str) -> None:
        """``USER <name>``: remember the name; ``331`` asks for ``PASS``.

        A ``gsiftp://`` server refuses ``USER`` before the GSI handshake, as
        globus does: the user is the certificate, not the name. (GSI clients,
        this package's plugin included, send ``USER :globus-mapping:`` and
        ``PASS dummy``.)
        """
        if self.server.gsi is not None and self.security is None:
            raise _Reply("530 Must perform GSSAPI authentication.")
        self.user = arg
        raise _Reply(f"331 Password required for {arg}.")

    def do_PASS(self, arg: str) -> None:
        """``PASS <password>``: log in, or ``530 Login incorrect``.

        Who is accepted depends on how the server was built: under GSI the
        DN is looked up in ``gridmap`` (any DN maps to ``gsiuser`` without
        one, and the password is ignored); in clear, ``users`` maps names to
        passwords, or, without it, only ``anonymous``/``ftp`` get in with any
        password. The ``230`` names the mapped user, which tests check.
        """
        if self.user is None:
            raise _Reply("503 Login with USER first.")
        name: str | None = self.user
        if self.security is not None:
            dn = "".join(f"/{key}={value}" for key, value in self.identity)
            gridmap = self.server.gridmap
            name = "gsiuser" if gridmap is None else gridmap.get(dn)
        elif self.server.users is None:
            name = name if name in ("anonymous", "ftp") else None
        elif self.server.users.get(self.user) != arg:
            name = None
        if name is None:
            raise _Reply("530 Login incorrect.")
        self.logged_in = True
        raise _Reply(f"230 User {name} logged in.")

    def do_FEAT(self, arg: str) -> None:
        """``FEAT``: the server's ``features``, one per line (RFC 2389 ``211`` block)."""
        body = "".join(f" {feature}\r\n" for feature in self.server.features)
        raise _Reply(f"211-Extensions supported\r\n{body}211 End.")

    def do_QUIT(self, arg: str) -> None:
        """``QUIT``: ``221``, then close the control connection."""
        self.reply("221 Goodbye.")
        raise _Hangup()

    # -- session settings -----------------------------------------------------------------

    def do_NOOP(self, arg: str) -> None:
        """``NOOP``: ``200``; clients use it as a keep-alive and liveness probe."""
        raise _Reply("200 NOOP command successful.")

    def do_SYST(self, arg: str) -> None:
        """``SYST``: the ``215 UNIX Type: L8`` every Unix FTP server sends."""
        raise _Reply("215 UNIX Type: L8")

    def do_PWD(self, arg: str) -> None:
        """``PWD``: ``257 "<cwd>"``, the quoted form RFC 959 specifies."""
        raise _Reply(f'257 "{self.cwd}" is current directory.')

    def do_CWD(self, arg: str) -> None:
        """``CWD <dir>``: change the directory relative paths resolve against."""
        if not os.path.isdir(self.local(arg)):
            raise _Reply(f"550 {arg}: Not a directory.")
        self.cwd = os.path.normpath(os.path.join(self.cwd, arg))
        raise _Reply("250 CWD command successful.")

    def do_TYPE(self, arg: str) -> None:
        """``TYPE A|I``: accepted and ignored - every transfer is binary.

        Clients send ``TYPE I`` before transfers and ``TYPE A`` before
        listings; neither changes a byte here, as on globus.
        """
        if arg.upper() not in ("A", "I"):
            raise _Reply("504 Type not supported.")
        raise _Reply(f"200 Type set to {arg.upper()}.")

    def do_MODE(self, arg: str) -> None:
        """``MODE S|E``: stream (RFC 959) or extended block (GFD.20) mode.

        ``MODE E`` lets a transfer use several connections and out-of-order
        blocks; listings are still sent in ``MODE S`` (see :mod:`.namespace`).
        """
        if arg.upper() not in ("S", "E"):
            raise _Reply("504 Mode not supported.")
        self.mode = arg.upper()
        raise _Reply(f"200 Mode set to {self.mode}.")

    def do_DCAU(self, arg: str) -> None:
        """``DCAU N|A``: data-channel authentication (GFD.20).

        ``A`` authenticates every data connection with the delegated proxy
        and requires the peer to be the same DN, so it needs a delegated
        credential: without one it is refused, as globus refuses it. ``S``
        (authenticate as a named subject) is not supported.
        """
        wanted = arg.upper()
        if wanted not in ("N", "A") or (wanted == "A" and self.delegated is None):
            raise _Reply("504 Bad DCAU mode.")
        self.dcau = wanted
        raise _Reply(f"200 DCAU {wanted}.")

    def do_PBSZ(self, arg: str) -> None:
        """``PBSZ <size>``: RFC 2228's protection buffer size, echoed and ignored."""
        raise _Reply(f"200 PBSZ={arg}")

    def do_PROT(self, arg: str) -> None:
        """``PROT C|P``: clear or private (encrypted) data channels (RFC 2228).

        ``P`` wraps data in the data channel's TLS session, so like
        ``DCAU A`` it needs the delegated credential; ``S`` and ``E`` are
        refused with RFC 2228's ``536``.
        """
        wanted = arg.upper()
        if wanted not in ("C", "P") or (wanted == "P" and self.delegated is None):
            raise _Reply("536 Requested PROT level not supported.")
        self.prot = wanted
        raise _Reply(f"200 Protection level set to {wanted}.")

    def do_OPTS(self, arg: str) -> None:
        """``OPTS RETR Parallelism=n,...;`` and ``OPTS PASV AllowDelayed=0|1;``.

        Parallelism's first number (GFD.20 gives starting, minimum and
        maximum) sets how many ``MODE E`` streams this server opens as a
        sender and expects as a receiver. ``AllowDelayed=1`` (a globus
        extension gfal2 always sends) makes ``PASV`` answer ``200 Passive
        delayed`` and the transfer command send the address as a ``127``.
        """
        what, _, value = arg.partition(" ")
        name, _, setting = value.partition("=")
        if what.upper() == "RETR" and name == "Parallelism":
            self.parallelism = max(1, int(setting.split(",")[0]))
        elif what.upper() == "PASV" and name == "AllowDelayed":
            self.allow_delayed = setting.rstrip(";") == "1"
        else:
            raise _Reply("501 Invalid command arguments.")
        raise _Reply("200 OPTS Command Successful.")

    def do_SITE(self, arg: str) -> None:
        """The globus ``SITE`` commands a client sends.

        ``CLIENTINFO`` (sent after login) and ``RETRBUFSIZE``/``STORBUFSIZE``
        (TCP buffer hints) are acknowledged and ignored. ``CHMOD <octal>
        <path>`` really changes the file. ``USAGE`` reports the root's disk,
        or the server's fixed ``usage`` reply, which tests use to feed odd
        answers. ``SETNETSTACK`` accepts any driver except ``udt``, which
        globus refuses unless whitelisted (the server's ``udt`` flag).
        """
        what, _, rest = arg.partition(" ")
        what = what.upper()
        if what == "CLIENTINFO":
            raise _Reply("250 OK.")
        if what == "CHMOD":
            mode, _, path = rest.partition(" ")
            try:
                os.chmod(self.local(path), int(mode, 8))
            except OSError as exc:
                raise self.failure(exc, "chmod") from None
            raise _Reply("200 SITE CHMOD command successful.")
        if what == "USAGE":
            if self.server.usage is not None:
                raise _Reply(self.server.usage)
            usage = shutil.disk_usage(self.server.root)
            raise _Reply(f"250 USAGE {usage.used} FREE {usage.free} TOTAL {usage.total}")
        if what in ("RETRBUFSIZE", "STORBUFSIZE"):
            raise _Reply(f"200 {what} {rest} OK.")
        if what == "SETNETSTACK":
            if rest.lower() == "udt" and not self.server.udt:
                raise _Reply("500 Command failed : udt driver not whitelisted")
            raise _Reply("200 Site Command Successful.")
        raise _Reply("500 Invalid command.")

    def do_ALLO(self, arg: str) -> None:
        """``ALLO <size>``: RFC 959 storage allocation, a no-op on a file system."""
        raise _Reply("200 ALLO command successful.")

    def do_REST(self, arg: str) -> None:
        """``REST <offset>``: RFC 3659 ``REST STREAM``; the next transfer starts there.

        The offset applies to the next ``RETR`` (skip that much) or ``STOR``
        (write from there without truncating), and is reset by any transfer.
        """
        self.rest = int(arg)
        raise _Reply("350 Restart Marker OK. Send STORE or RETRIEVE to initiate transfer.")

    def do_ABOR(self, arg: str) -> None:
        """``ABOR``: ``226``; there is never a transfer to abort by the time it is read.

        Transfers run to completion on this session's thread before the next
        command is read, so a client's ``ABOR`` always finds the server idle.
        """
        raise _Reply("226 Abort successful.")
