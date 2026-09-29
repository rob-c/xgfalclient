"""gfal2's http plugin in pure Python: WebDAV, HTTP TPC, S3, tape REST and tokens.

The modules, in the order a request meets them:

* :mod:`._client` - pooled ``http.client`` connections, credentials, redirects;
* :mod:`.plugin` - :class:`HTTPPlugin`, the namespace and dispatch;
* :mod:`._dav` - multistatus and ``Digest`` parsing;
* :mod:`._io` - open files: ranged reads, streamed and spooled uploads;
* :mod:`._copy` - uploads, parallel downloads, third-party copies;
* :mod:`._tape`, :mod:`._token`, :mod:`._delegation`, :mod:`._s3`, :mod:`._qos`.
"""

from __future__ import annotations

from .plugin import HTTPPlugin

__all__ = ["HTTPPlugin"]
