"""Google Cloud Storage: ``gcloud://`` and ``gclouds://``, as davix speaks them.

davix does not fetch OAuth2 access tokens for GCS. It signs every request
as a *V4 signed URL* (``GOOG4-RSA-SHA256``) with the service account's own
RSA key, and talks to the XML API - the S3-compatible one - with path-style
URLs (``gclouds://storage.googleapis.com/<bucket>/<key>``). This does the
same, so a site's existing gfal2 configuration works unchanged: the
service-account JSON comes from ``[GCLOUD] JSON_AUTH_FILE`` or
``JSON_AUTH_STRING``, and only its ``client_email`` and ``private_key`` are
used. Signing is :meth:`~xgfalclient.crypto.rsa.RSAPrivateKey.sign` with
SHA-256, and nothing leaves the process but the signature.

With no credentials configured, requests go unsigned (a public bucket).
"""

from __future__ import annotations

import errno
import hashlib
import json
import threading
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ...crypto.rsa import RSAPrivateKey, load_private_key
from ...errors import GError
from ._client import Body, Target

if TYPE_CHECKING:
    from ...options import Options

__all__ = ["GCloudKeys", "GCloudSigner", "is_gcloud", "load_keys", "KeyCache"]

ALGORITHM = "GOOG4-RSA-SHA256"
#: How long a signed URL stays valid.
EXPIRES = 3600


def is_gcloud(scheme: str) -> bool:
    return scheme.partition("+")[0] in ("gcloud", "gclouds")


@dataclass(frozen=True)
class GCloudKeys:
    client_email: str
    key: RSAPrivateKey

    def __repr__(self) -> str:
        return f"GCloudKeys({self.client_email!r}, key=<redacted>)"


def load_keys(text: str, where: str) -> GCloudKeys:
    """``client_email`` and ``private_key`` out of a service-account JSON document."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise GError(
            f"Failed to load configured GCloud credentials: {where}: {exc}", errno.EINVAL
        ) from exc
    if not isinstance(document, dict):
        raise GError(
            f"Failed to load configured GCloud credentials: {where} is not a JSON object",
            errno.EINVAL,
        )
    for name in ("client_email", "private_key"):
        if not isinstance(document.get(name), str) or not document[name]:
            raise GError(
                f"Failed to load configured GCloud credentials: Could not find {name}",
                errno.EINVAL,
            )
    try:
        key = load_private_key(document["private_key"])
    except ValueError as exc:
        raise GError(f"Failed to load configured GCloud credentials: {exc}", errno.EINVAL) from exc
    return GCloudKeys(document["client_email"], key)


class KeyCache:
    """The configured service account, parsed once per distinct configuration."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], GCloudKeys] = {}

    def get(self, options: Options) -> GCloudKeys | None:
        path = options.string("GCLOUD", "JSON_AUTH_FILE")
        inline = options.string("GCLOUD", "JSON_AUTH_STRING")
        if not path and not inline:
            return None
        with self._lock:
            found = self._cache.get((path, inline))
        if found is not None:
            return found
        if path:
            try:
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
            except OSError as exc:
                raise GError(
                    f"Could not read gcloud credentials at '{path}': {exc.strerror}",
                    exc.errno or errno.EIO,
                ) from exc
            found = load_keys(text, path)
        else:
            found = load_keys(inline, "JSON_AUTH_STRING")
        with self._lock:
            self._cache[(path, inline)] = found
        return found


def _stamp(when: datetime | None) -> str:
    return (when or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


class GCloudSigner:
    """Turns requests into V4 signed URLs for one service account."""

    def __init__(self, keys: GCloudKeys, *, expires: int = EXPIRES) -> None:
        self.keys = keys
        self.expires = expires

    def signed_path(self, method: str, target: Target, when: datetime | None = None) -> str:
        """``target.path`` with the ``X-Goog-*`` query that authorises ``method`` on it."""
        stamp = _stamp(when)
        scope = f"{stamp[:8]}/auto/storage/goog4_request"
        path, _, query = target.path.partition("?")
        params = urllib.parse.parse_qsl(query, keep_blank_values=True)
        params += [
            ("X-Goog-Algorithm", ALGORITHM),
            ("X-Goog-Credential", f"{self.keys.client_email}/{scope}"),
            ("X-Goog-Date", stamp),
            ("X-Goog-Expires", str(self.expires)),
            ("X-Goog-SignedHeaders", "host"),
        ]
        canonical_query = "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted(params))
        canonical = "\n".join(
            [
                method.upper(),
                path,
                canonical_query,
                f"host:{target.host_header}\n",
                "host",
                "UNSIGNED-PAYLOAD",
            ]
        )
        to_sign = "\n".join(
            [ALGORITHM, stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()]
        )
        signature = self.keys.key.sign(to_sign.encode(), digest="sha256").hex()
        return f"{path}?{canonical_query}&X-Goog-Signature={signature}"

    # -- the signer protocol the HTTP client drives ------------------------------------

    def target(self, method: str, target: Target) -> Target:
        return replace(target, path=self.signed_path(method, target))

    def sign(
        self, method: str, target: Target, headers: Mapping[str, str], body: Body | None
    ) -> dict[str, str]:
        return {}  # the authorisation is in the URL

    def presign(self, method: str, url: str, expires: int = EXPIRES) -> str:
        target = Target.of(url, s3=True)
        signer = GCloudSigner(self.keys, expires=min(max(expires, 1), 604800))
        return f"{target.base}{signer.signed_path(method, target)}"
