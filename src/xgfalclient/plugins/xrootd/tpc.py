"""A third-party copy, ``root`` to ``root``: XrdCl's ``ThirdPartyCopyJob``, step by step.

The destination pulls the file from the source; this process only brokers
the rendezvous and waits. :class:`Rendezvous` is the job (XRootD 5.9's
``CanDo``, then ``RunTPC`` or ``RunLite``), run on a worker thread by
:func:`pull` while the copy's own thread watches the clock, the context's
``cancel()`` and the progress callback.

Why not :func:`xrdclient.third_party`? It runs the same rendezvous, but not
the way gfal2 users see it, and the differences are observable:

* it opens both ends on their paths alone, so the URL's CGI - an
  ``authz=`` token, gfal2's ``svcClass`` space token, the
  ``[XROOTD PLUGIN] XRD.*`` options - never reaches either server, where
  XrdCl merges its own fields over the URL's;
* after a refused copy it removes an empty destination - one that was
  there before, too, when the copy was refused for not overwriting it - and
  asks with the source's credentials;
* it asks the destination's ``tpc tpcdlg`` only when delegating, never the
  source's ``tpc``, and names the source as the end that failed its
  placement open, where XrdCl names none.

So the steps are spelled out here, over xrdclient's public
:class:`~xrdclient.File` and :class:`~xrdclient.FileSystem`; the session
multiplexes, so the ``ofs.tpc cancel`` that stops a pull goes out on the
pull's own handle beside the sync it interrupts.
"""

from __future__ import annotations

import contextlib
import errno
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import xrdclient
from xrdclient import errors as xe

from ...errors import GError
from .. import xrootd as package
from .errors import CopyError, Failure, describe, unsupported
from .urls import host_id, landed, opaque

if TYPE_CHECKING:
    from xrdclient import Config, XRootDURL
    from xrdclient.client.file import File

    from ...transfer import Transfer

#: What XrdCl's ``Fcntl`` sends a pull's destination to stop it: the string
#: with its NUL, which ``XrdOfsFile::fctl`` insists on.
TPC_CANCEL = b"ofs.tpc cancel\x00"

#: ``kXR_open`` options, spelled out so an open is one integer.
_READ, _UPDATE, _NEW, _DELETE = 0x0010, 0x0020, 0x0008, 0x0002


@dataclass(frozen=True, slots=True)
class End:
    """One end of a rendezvous: the URL to open and the settings to open it with.

    The two ends log in separately and may differ in credentials and
    timeouts (the destination's login delegates when the source's does
    not), so each URL travels with its own :class:`~xrdclient.Config`.
    """

    url: XRootDURL
    config: Config


class Rendezvous:
    """XrdCl's ``ThirdPartyCopyJob`` (XRootD 5.9): ``CanDo``, then ``RunTPC`` or ``RunLite``.

    1. The source is opened with ``tpc.stage=placement`` and closed, which
       finds its data server (``tpcSource``) and size. Without delegation a
       failure here is the job's; with it the source is left to the
       destination to reach with the delegated proxy (TPC lite *only*).
    2. The destination is opened (``kXR_open_updt`` and ``kXR_new``, or
       ``kXR_delete`` for ``overwrite``) with ``cgiC2Dst``'s CGI: the key, the
       source, ``tpc.dlgon`` saying whether the client delegates, and, when
       it does, the source's CGI as ``tpc.scgi``. With delegation on the
       login delegates the proxy (XrdCl sets ``XrdSecGSIDELEGPROXY=1`` for
       it, ``0`` without), so a destination configured with
       ``ofs.tpc fcreds`` holds a proxy of its own to pull with.
    3. ``kXR_Qconfig`` ``tpc tpcdlg`` at the destination (``CheckTPCLite``):
       no TPC is "Destination does not support third-party-copy."; TPC and
       ``tpcdlg`` set, with delegation on, is TPC lite; anything else is the
       classic copy, which a source that could not be opened cannot have
       ("Destination does not support delegation.") and which needs the
       source to answer ``tpc`` (``CheckTPC``).
    4. Classic: ``kXR_sync`` arms the pull, the source is opened with the
       key and ``tpc.dst`` (``cgiC2Src``), and a second ``kXR_sync`` blocks
       until the destination has the file. Lite: the two syncs, and the
       source is not contacted at all.

    Failures carry XrdCl's side: ``(destination)`` for the destination's
    open, first sync and close, ``(source)`` for the source's keyed open and
    close, and nothing for the placement or the pull itself (the second
    sync).

    :meth:`call_off`, from another thread, stops the job: before the pull
    it is never started, and once it is under way the destination is sent
    what XrdCl's ``RunTPC``/``RunLite`` send when their progress handler's
    ``ShouldCancel`` says so (gfal2's says so once the context is
    cancelled): ``File::Fcntl("ofs.tpc cancel")``. ``XrdOfsFile::fctl``
    then kills the pull and answers the waiting sync ``ECANCELED``
    ("destination file prematurely closed"), which is the pull's failure;
    the fctl's own answer is ignored, as XrdCl only logs it. Either way the
    handles are then closed.
    """

    def __init__(self, source: End, target: End, *, delegate: bool, overwrite: bool) -> None:
        """A job between two ends, not yet started; :meth:`run` may be called more than once.

        ``delegate`` is gfal2's ``proxy_delegation`` for this pair (the
        target's config must already say ``gsi_delegate`` to match, since
        that is decided at login); ``overwrite`` opens the destination with
        ``kXR_delete`` instead of ``kXR_new``. The copy runs the job a
        second time after making a missing parent, so nothing here is
        consumed by a run except the pull's handle, which is per run.
        """
        self.source = source.url
        self.target = target.url
        self.source_config = source.config
        self.target_config = target.config
        self.delegate = delegate
        self.overwrite = overwrite
        # Guards ``_pulling`` and ``_stopped`` between the worker running the
        # job and the copy's thread calling it off.
        self._lock = threading.Lock()
        #: The pull's handle while its second sync waits, for :meth:`call_off`.
        self._pulling: File | None = None
        self._stopped = False

    def run(self, timeout: float | None) -> int:
        """The whole job; the size of the source, as far as the job knew it."""
        source_config, target_config = self._configs(timeout)
        size, where = self._place(source_config)
        origin = where or self.source  # tpcSource
        # The rendezvous key both ends quote: the destination arms the pull
        # under it, the source admits only the destination that knows it.
        # Unguessable, since anyone holding it could read the source.
        key = uuid.uuid4().hex[:24]
        pull = xrdclient.File(
            opaque(self.target, self._fields(key, origin, size, where)), target_config
        )
        try:
            pull.open(_UPDATE | (_DELETE if self.overwrite else _NEW), 0o644)
        except Exception as exc:
            raise _refused(exc) from exc
        # The data server the destination's open was redirected to: the one
        # that will pull, and so the one the source must expect (``tpc.dst``).
        puller = landed(self.target, pull.endpoint)
        lite = self._settle(
            pull, End(puller, target_config), End(origin, source_config), where is not None
        )
        _step(pull.sync, "destination", pull)
        ends = [(pull, "destination")]
        if not lite:
            keyed = xrdclient.File(
                opaque(origin, {"tpc.key": key, "tpc.dst": puller.host, "tpc.stage": "copy"}),
                source_config,
            )
            _step(lambda: keyed.open(_READ), "source", pull)
            ends.insert(0, (keyed, "source"))
        _step(lambda: self._await(pull), "", *(handle for handle, _ in ends))
        # Both ends are closed even when the first close fails, and the
        # first failure, source before destination, is the one raised.
        failures = [_closed(handle, end) for handle, end in ends]
        for failure in failures:
            if failure is not None:
                raise failure
        return max(size, 0)

    def call_off(self) -> None:
        """Stop the job from another thread; see the class's account."""
        with self._lock:
            self._stopped = True
            pulling = self._pulling
        if pulling is not None:
            _quietly(lambda: pulling.fcntl(TPC_CANCEL))

    def _configs(self, timeout: float | None) -> tuple[Config, Config]:
        """Each end's settings for this run: the copy's time left bounds every request.

        A request timeout bounds one wait on the connection, and the pull is
        one long wait for the destination's answer. Its end is given longer:
        the copy's own clock, which :func:`pull` watches, must run out first,
        so that a pull out of time is called off as XrdCl calls it off rather
        than having its wait expire under it; and with no time limit on the
        copy at all it waits up to :data:`TPC_TIMEOUT`, as XrdCl's
        ``CPTPCTimeout`` bounds the sync its ``RunTPC`` blocks in.
        """
        if not timeout:
            patience = max(self.target_config.request_timeout, package.TPC_TIMEOUT)
            return self.source_config, self.target_config.evolve(request_timeout=patience)
        return (
            self.source_config.evolve(request_timeout=timeout),
            self.target_config.evolve(request_timeout=timeout + package.TPC_CANCEL_WAIT),
        )

    def _place(self, config: Config) -> tuple[int, XRootDURL | None]:
        """The size and landing place of the source, or ``None`` for one that cannot be opened."""
        placed = xrdclient.File(opaque(self.source, {"tpc.stage": "placement"}), config)
        try:
            placed.open(_READ)
            size = int(placed.size)
        except Exception as exc:
            if not self.delegate:
                raise CopyError(describe(exc), "") from exc
            return -1, None
        _quietly(placed.close)
        return size, landed(self.source, placed.endpoint)

    def _fields(
        self, key: str, origin: XRootDURL, size: int, where: XRootDURL | None
    ) -> dict[str, str]:
        """``cgiC2Dst``: what tells the destination who to pull from, in XrdCl's order."""
        fields = {
            "tpc.key": key,
            "tpc.src": host_id(origin),
            "tpc.lfn": origin.path,
            **_streams(os.environ.get("XRD_SUBSTREAMSPERCHANNEL", "")),
            "tpc.dlg": host_id(self.source),
            "tpc.spr": self.source.scheme,
            "tpc.tpr": self.target.scheme,
            "tpc.dlgon": "1" if self.delegate else "0",
        }
        if where is not None:
            fields["oss.asize"] = str(size)
        fields["tpc.stage"] = "copy"
        scgi = "\t".join(
            sorted(f for f in self.source.cgi.split("&") if not f.startswith("xrdcl."))
        )
        if scgi and self.delegate:
            fields["tpc.scgi"] = scgi
        return fields

    def _settle(self, pull: File, puller: End, origin: End, placed: bool) -> bool:
        """Step 3: TPC lite, the classic copy, or neither (the pull's handle closed, unheard).

        ``puller`` is the data server the destination's open landed on and
        ``origin`` the source's (``tpcSource``), each with this run's
        settings: XrdCl asks the server that will do the work, not the
        redirector the URL named. ``placed`` is whether the placement open
        found the source at all.
        """
        lite = _tpc_lite(_ask_config(puller.url, "tpc tpcdlg", puller.config))
        refusal = ""
        if lite is None:
            refusal = "Destination does not support third-party-copy."
        elif not (lite and self.delegate) and not placed:
            refusal = "Destination does not support delegation."
        elif not (lite and self.delegate) and not _tpc(
            _ask_config(origin.url, "tpc", origin.config)
        ):
            refusal = "Source does not support third-party-copy"
        if refusal:
            _quietly(pull.close)
            raise unsupported(refusal)
        return bool(lite and self.delegate)

    def _await(self, pull: File) -> None:
        """The pull itself - the destination's second ``kXR_sync`` - unless already called off."""
        with self._lock:
            if self._stopped:
                return
            self._pulling = pull
        try:
            pull.sync()
        finally:
            with self._lock:
                self._pulling = None


def pull(transfer: Transfer, job: Rendezvous, report: Callable[[], None]) -> int:
    """Run ``job`` in a worker while this thread watches the clock; the source's size.

    The rendezvous blocks until the destination has the file, so it runs
    in a worker while this thread keeps ``transfer.check()`` honest and,
    when someone is listening, calls ``report`` every :data:`TPC_PROGRESS`
    seconds. A copy that must stop - cancelled, out of time, or a callback
    that raised - calls the job off (see :class:`Rendezvous`) and fails the
    way gfal2's does: a cancelled pull with the destination's answer to the
    cancel (``ECANCELED``, "destination file prematurely closed"), one out
    of time as XrdCl's expired ``kXR_sync`` (``[ERROR] Operation
    expired``), and a callback's exception as it was. A destination that
    does not answer the cancel within :data:`TPC_CANCEL_WAIT` is left to
    it, as before XrdCl learned to cancel.
    """
    outcome: list[Any] = []
    timeout = transfer.remaining()

    def work() -> None:
        """The job on the worker; its size or its exception, for the waiting thread."""
        try:
            outcome.append(job.run(timeout))
        except BaseException as exc:  # handed to the waiting thread
            outcome.append(exc)

    # A daemon: a destination that never answers the cancel must not keep the
    # interpreter alive at exit after the copy has already failed.
    worker = threading.Thread(target=work, name="xgfal-tpc", daemon=True)
    worker.start()
    watching = transfer.params.monitor_callback is not None
    asked = time.monotonic()
    while worker.is_alive():
        worker.join(package.TPC_POLL)
        try:
            transfer.check()
        except Exception as exc:
            job.call_off()
            worker.join(package.TPC_CANCEL_WAIT)
            raise _stopped(exc, outcome) from None
        if watching and worker.is_alive() and time.monotonic() - asked >= package.TPC_PROGRESS:
            asked = time.monotonic()
            report()
    # The worker has finished, so ``outcome`` holds exactly its one result.
    result = outcome.pop()
    if isinstance(result, BaseException):
        raise result
    return int(result)


def _stopped(exc: Exception, outcome: list[Any]) -> Exception:
    """The failure of a pull stopped by ``exc``, as gfal2 reports it (see :func:`pull`)."""
    if not isinstance(exc, GError):
        return exc  # a callback's own exception
    if exc.code == errno.ETIMEDOUT:
        return CopyError(Failure(errno.ETIMEDOUT, "[ERROR] Operation expired", ""), "")
    answered = outcome[-1] if outcome else None
    return answered if isinstance(answered, CopyError) else exc


def _streams(value: str) -> dict[str, str]:
    """``tpc.str``: XrdCl's ``SubStreamsPerChannel`` less the control stream, when any are left.

    XrdCl reads it from ``XRD_SUBSTREAMSPERCHANNEL`` with ``strtol`` (base 0)
    and ignores a value that is not all number; gfal2's ``nbstreams`` goes
    to a job property the third-party job never reads.
    """
    try:
        count = int(value, 0)
    except ValueError:
        try:
            count = int(value, 8)  # strtol's octal "010"
        except ValueError:
            count = 1
    return {"tpc.str": str(count - 1)} if count > 1 else {}


def _ask_config(url: XRootDURL, names: str, config: Config) -> str | None:
    """A ``kXR_Qconfig`` answer up to its first NUL, or ``None`` if the query failed."""
    # A FileSystem of its own on the data server named, not a pooled one:
    # the question is for that very server, not whichever the pool knows.
    fs = xrdclient.FileSystem(url.without_query().with_path("/"), config)
    try:
        answer = bytes(fs.query(7, names))  # 7 is kXR_Qconfig
    except Exception:
        return None
    finally:
        fs.close()
    return answer.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _atoi(text: str) -> int:
    """C's ``atoi`` after XrdCl's ``isdigit`` of the first character: leading digits, or 0."""
    count = len(text) - len(text.lstrip("0123456789"))
    return int(text[:count]) if count else 0


def _tpc_lite(answer: str | None) -> bool | None:
    """``XrdCl::Utils::CheckTPCLite``: no TPC (``None``), TPC (``False``), or TPC lite.

    The server answers each name on its line, echoing a name it has no value
    for; ``tpcdlg`` is set to the protocol whose credentials it forwards.
    """
    lines = [line for line in (answer or "").split("\n") if line]
    if not lines or not _atoi(lines[0]):
        return None
    return len(lines) > 1 and lines[1] != "tpcdlg"


def _tpc(answer: str | None) -> bool:
    """``XrdCl::Utils::CheckTPC``, including its refusal of a one-character answer."""
    return answer is not None and len(answer) != 1 and _atoi(answer) != 0


def _refused(exc: Exception) -> CopyError:
    """The destination's open failing, as XrdCl reports it."""
    code, text = (exc.code, exc.message) if isinstance(exc, xe.ServerError) else (0, "")
    if code == xe.kXR_FSError and "tpc not supported" in text:
        return unsupported("Destination does not support third-party-copy.")
    return CopyError(describe(exc), "destination", no_parent=code == xe.kXR_NotFound)


def _step(action: Callable[[], object], end: str, *handles: File) -> None:
    """One step of the rendezvous; on failure the open handles are closed, unheard."""
    try:
        action()
    except Exception as exc:
        for handle in handles:
            _quietly(handle.close)
        raise CopyError(describe(exc), end) from exc


def _closed(handle: File, end: str) -> CopyError | None:
    """Close one end; its failure, named for that end, if it failed."""
    try:
        handle.close()
    except Exception as exc:
        return CopyError(describe(exc), end)
    return None


def _quietly(action: Callable[[], object]) -> None:
    """A close (or a cancel) whose outcome XrdCl ignores."""
    with contextlib.suppress(Exception):
        action()
