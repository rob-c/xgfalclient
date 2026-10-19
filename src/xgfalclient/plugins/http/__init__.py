"""gfal2's http plugin in pure Python: WebDAV, HTTP TPC, S3, GCS, Swift, CS3, tape REST, tokens.

The modules, in the order a request meets them (the parsing, transfer and
tape vocabulary underneath is xrdhttp's, shared with xrdclient's HTTP client):

* :mod:`._client` - pooled ``http.client`` connections, credentials, redirects,
  with :mod:`._target` (where a request goes) and :mod:`._status` (davix's
  errors) beside it;
* :mod:`.plugin` - :class:`HTTPPlugin`, the namespace and dispatch;
* :mod:`._dav` - multistatus and ``Digest`` parsing;
* :mod:`._io` - open files: ranged reads, streamed and spooled uploads;
* :mod:`._copy` - gfal2's copy: preparation, the modes and their fallback,
  checksums; the attempts themselves are :mod:`._streamed` (bytes through
  this process), :mod:`._ranged` (parallel ranged downloads to ``file://``)
  and :mod:`._tpc` (third-party ``COPY``);
* :mod:`._tape`, :mod:`._token`, :mod:`._delegation`, :mod:`._s3`, :mod:`._gcloud`,
  :mod:`._swift`, :mod:`._qos`.
"""

from __future__ import annotations

from .plugin import HTTPPlugin

__all__ = ["HTTPPlugin"]
