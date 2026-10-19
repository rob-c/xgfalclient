"""``root://``, ``roots://``, ``xroot://`` and ``xroots://``, spoken by xrdclient.

gfal2's xrootd plugin is a thin layer over ``libXrdCl`` (and ``XrdPosix``,
which it uses for most of the namespace). This one is the same thin layer
over `xrdclient <https://github.com/rob-c/xrdclient>`_, the same author's
pure-Python XRootD client, which is a required dependency. A broken
installation still reports an actionable repair message: the plugin
registry (:mod:`xgfalclient.plugins`) imports this package by name and
answers :data:`~xgfalclient.plugins.XROOTD_HINT` when it cannot.

Where things are
----------------

This package is the facade: everything ``xgfalclient.plugins.xrootd``
has ever offered is importable from here, and the tunables below are read
from here *at call time*, so a caller (or a test) that sets
``xrootd.UPLOAD_CHUNK`` changes what the next upload does. The work is in
the modules beside it, each with its own account of why it is the way it is:

* :mod:`.plugin` - :class:`XRootDPlugin`: the xrdclient settings for a URL,
  the idle filesystems kept between calls, and every namespace, I/O,
  metadata and staging call, each a few lines over xrdclient.
* :mod:`.errors` - how a failure from below is worded and numbered, in
  each of XrdCl's spellings, and the ``errno`` of every ``kXR_*`` code.
* :mod:`.stat` - a server's stat, listing, checksum and space answers as
  ``XrdPosix`` and gfal2 present them.
* :mod:`.file` - :class:`XRootDFile`, an open file, and how ``cancel()``
  reaches what a call is blocked on.
* :mod:`.copy` - a copy, as gfal2 hands it to XrdCl's copy process:
  narration, checksums, downloads and uploads, the clean-up after a failure.
* :mod:`.tpc` - the third-party copy (``root`` to ``root``), XrdCl's
  ``ThirdPartyCopyJob`` step by step.
* :mod:`.tape` - bring-online, its polls, release and abort.
* :mod:`.urls` - URL spellings: schemes, local paths, opaque CGI.

Everything here goes through xrdclient's public API, and the read-ahead
uploads use is :class:`xrdcore.pipeline.ReadAhead`, the one xrdclient's own
copy engine uses - no private module of xrdclient's.

What gfal2 does, and what this does
-----------------------------------

Everything a user can observe is gfal2's, read off its source (2.23.5) and
checked against it:

* **Errors.** A server's ``kXR_*`` code becomes an ``errno`` through
  ``XProtocol::toErrno`` exactly as ``XrdPosix`` maps it, and the message is
  worded as that operation words it in gfal2 (``Failed to stat file (No such
  file or directory)``). The client-side failures take ``XrdPosix``'s mapping
  of the corresponding ``XrdCl`` status: a refused connection is
  ``ECONNREFUSED``, an unresolvable host ``EHOSTUNREACH``, a failed login
  ``EAUTH``.
* **Stat.** ``st_mode`` is built from the XRootD flags the way
  ``XrdPosixMap::Flags2Mode`` builds it - owner bits only - with the caller's
  uid and gid and ``nlink`` 1, and a directory listing's entries carry the
  reduced stat gfal2's ``readdirpp`` fills in.
* **Quirks kept.** ``mkdir`` stats first and answers ``EEXIST`` itself (EOS
  says yes to an existing directory), always creates parents, and ``rmdir``
  massages ``errno`` the way gfal2 does. Extended attributes are the four
  gfal2 invents (``xroot.cksum``, ``xroot.space``, ``xroot.xattr``,
  ``spacetoken``) plus ``user.status``; ``setxattr`` is ``ENOSYS``.
* **Copies.** gfal2 hands a copy to XrdCl whole, and so does this plugin
  to itself: the core checks no destination and computes no checksum.
  ``root`` to ``root`` is a third-party copy (``TRANSFER:TYPE`` ``3rd
  pull``); any other pair of XRootD schemes is announced as ``streamed``, as
  gfal2 announces a job XrdCl may run either way; ``root`` to and from
  ``file://`` streams through this process. The events are XrdCl's: the
  prepared URLs on ``TRANSFER:ENTER``, ``Job finished, [SUCCESS]`` or the
  error on ``TRANSFER:EXIT``, ``EVICT`` after it (``-1`` for a local
  source), and gfal2's own ``CLEANUP``. An existing destination is refused
  by whoever holds it (``EEXIST``, nothing cleaned), a pull and an upload
  make the destination's path and a download the local one, whatever
  ``create_parent`` says. Checksums are XrdCl's ``checkSumMode``: no
  ``CHECKSUM`` events, and a mismatch is ``EILSEQ`` (``[ERROR] CheckSum
  error``). A pull is XrdCl's third-party job step by step (see
  :mod:`.tpc`): with ``proxy_delegation`` on (gfal2 sets XrdCl's
  ``delegate`` from it for ``root`` to ``root``) the destination's login
  delegates the proxy and its open says ``tpc.dlgon=1``, and a destination
  that advertises ``tpcdlg`` pulls with that proxy ("TPC lite") - no key,
  and a source this client cannot open itself is no obstacle. Otherwise it
  is the classic rendezvous, and a source that cannot be opened is
  "Destination does not support delegation.". A pull that must stop -
  ``cancel()``, the copy's timeout, a callback that raised - sends the
  destination XrdCl's ``ofs.tpc cancel`` on the pull's handle, waits for
  its answer and closes the handles: a cancelled pull fails with that
  answer (``ECANCELED``, "destination file prematurely closed"), one out of
  time as XrdCl's expired sync (``[ERROR] Operation expired``), and the
  clean-up then finds nothing busy to remove. ``XRD_SUBSTREAMSPERCHANNEL``
  above 1 asks the destination for that many streams less one
  (``tpc.str``). A download runs on xrdclient's bulk data plane, pipelined
  over ``nbstreams`` connections (two by default) and landed straight in
  the file, which is where this is an order of magnitude faster than gfal2;
  an upload is one handle, because xrootd admits one writer per file, with
  several writes in flight on it and nothing copied on the way. Either is
  stopped by ``cancel()`` at once, not at its next chunk: the handles in
  flight are aborted.

Where gfal2 is wrong, this is not, and says so where it differs:
``gfal2_xrootd_set_error`` reports whatever the global ``errno`` happens to
hold rather than the code it was given, which is how ``chmod`` of a missing
file comes back as ``EILSEQ``; the code given is used here. A timeout is
``ETIMEDOUT`` (``XrdPosix`` says ``ETIME``, gfal2's own map ``ESTALE``). A
listing entry's mode keeps ``S_IFREG`` so that its ``d_type`` is ``DT_REG``,
which gfal2 reports without the mode to match. A local file's failure in a
copy carries its real ``errno``: gfal2 passes XrdCl's ``kXR_*`` number on
(3018 for an existing file), fails to see ``EEXIST`` in it, and deletes the
local file it has just refused to overwrite; here the file is kept and
nothing is cleaned. The ``CLEANUP`` after a failed download is ``0`` for a
file that was never made, where gfal2 reports 3011. A pull out of time
stops at the copy's deadline with the same cancel a cancelled one sends;
XrdCl lets its sync expire (on a timer that ticks every 15 seconds) and
closes the destination, which the server takes the same way. A classic
pull whose close fails names the end that failed it; XrdCl's ``RunTPC``
names the other one. A pull's destination login delegates exactly when
``proxy_delegation`` says so, as XrdCl intends when it sets
``XrdSecGSIDELEGPROXY`` for the job; in gfal2 that comes too late, since
XrdSecgsi reads the variable once, at the process's first GSI login (the
source's), so its bindings delegate only when the variable was exported
beforehand, and then even with ``proxy_delegation`` off (``gfal-copy
--no-delegation`` still hands the destination a proxy).

Not done, deliberately: ``[XROOTD PLUGIN] NORMALIZE_PATH=false`` (gfal2
then sends ``root://h/p`` as the relative path ``p``, which a stock server
refuses); ``PARALLEL_COPIES`` (a bulk copy runs one file at a time through
the core); falling back from a pull to a stream for non-``root`` pairs
(XrdCl's ``thirdParty=first``), which gfal2 does not do against a stock
server either; the ``xrd.gsiusrpxy=`` (or ``xrd.gsiusrcrt=``/``gsiusrkey=``)
CGI gfal2 adds to a URL whose X.509 credential came from ``cred_set``: the
credential reaches xrdclient through its configuration instead (a
separate certificate and key as they are, never copied to disk), so only
the copy events' URLs read differently. XrdCl sets
``XrdSecGSIDELEGPROXY`` process-wide for a pull, so that every later login
in the process follows the last pull's setting; here only the pull's
destination login does, and everything else follows the environment
(``gfal-copy`` exports ``XrdSecGSIDELEGPROXY=1``, as upstream's does, which
xrdclient honours by signing the server's proxy request at login, as XrdCl
does).
"""

from __future__ import annotations

from .. import XROOTD_HINT
from .copy import EVICT, TYPE_PULL, TYPE_STREAMED
from .errors import (
    EAUTH,
    EBADRQC,
    ENOATTR,
    ETIME,
    KXR_ERRNO,
    Failure,
    describe,
    e2t,
    posix_error,
    status_error,
)
from .file import XRootDFile
from .plugin import DOMAIN, XATTRS, XRootDPlugin
from .stat import (
    Brief,
    flags_to_mode,
    listing_stat,
    parse_listing,
    posix_stat,
    space_json,
    status_word,
)
from .tape import parse_prepare_status
from .tpc import TPC_CANCEL
from .urls import SCHEMES, collapse_slashes, is_root, local_path

# The submodules read the tunables below through this package
# (``from .. import xrootd as package``) at call time, never at import, so
# they may be imported before the tunables are bound.

# -- tunables: read through this module at call time -----------------------------

#: How often a third-party copy's waiter wakes to check the clock, and how
#: often it asks the destination how far the pull has got, in seconds.
TPC_POLL = 0.05
TPC_PROGRESS = 1.0
#: How long a stopped pull waits for the destination to answer its cancel.
TPC_CANCEL_WAIT = 60.0
#: How long a pull may wait on its destination when the copy has no
#: deadline of its own: XrdCl's ``CPTPCTimeout`` default, which bounds the
#: sync its ``RunTPC`` blocks in.
TPC_TIMEOUT = 1800.0

#: How many idle :class:`~xrdclient.FileSystem` objects to keep per endpoint and
#: identity, and for how many endpoints; see :meth:`XRootDPlugin._fs`.
IDLE_PER_ENDPOINT = 4
IDLE_ENDPOINTS = 32
#: How many parsed URLs to remember; see :meth:`XRootDPlugin._target`.
TARGET_CACHE = 512

#: An upload's request size and how many are in flight on its connection.
#: A megabyte keeps the one buffer in cache; four hide the round trip.
UPLOAD_CHUNK = 1 << 20
UPLOAD_DEPTH = 4
#: Buffers the upload's reader fills ahead of the sender.
UPLOAD_BUFFERS = 4

#: What ``root://`` says when this package (and so xrdclient) cannot be
#: imported. The plugin registry gives that answer, since a module that
#: failed to import can say nothing itself; this is the same text, kept here
#: for code that read it from this module before.
MISSING_HINT = XROOTD_HINT


__all__ = [
    "DOMAIN",
    "EAUTH",
    "EBADRQC",
    "ENOATTR",
    "ETIME",
    "EVICT",
    "KXR_ERRNO",
    "MISSING_HINT",
    "SCHEMES",
    "TPC_CANCEL",
    "TYPE_PULL",
    "TYPE_STREAMED",
    "XATTRS",
    # Everything else this module has always offered by name.
    "Brief",
    "Failure",
    "XRootDFile",
    "XRootDPlugin",
    "collapse_slashes",
    "describe",
    "e2t",
    "flags_to_mode",
    "is_root",
    "listing_stat",
    "local_path",
    "parse_listing",
    "parse_prepare_status",
    "posix_error",
    "posix_stat",
    "space_json",
    "status_error",
    "status_word",
]
