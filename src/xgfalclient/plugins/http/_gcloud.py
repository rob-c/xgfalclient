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

How a V4 signed URL is made (Google's "V4 signing process", the same shape
as AWS SigV4 with RSA in place of the HMAC chain): a *canonical request* -
method, path, the sorted and percent-encoded query including the
``X-Goog-*`` parameters, the signed headers (``host`` only), their names,
and ``UNSIGNED-PAYLOAD`` - is hashed with SHA-256; the *string to sign* is
the algorithm, the timestamp, the credential scope
(``<date>/auto/storage/goog4_request``) and that hash; the signature is
RSASSA-PKCS1-v1_5 with SHA-256 (what JOSE calls RS256) over it, in hex.
Because only ``host`` is signed and the payload is not, the same URL works
for any body and through any proxy that keeps the Host - which is also why
it can be handed to the far side of a third-party copy as it is.

Failure modes: a missing or malformed service-account document is
``EINVAL`` (gfal2's "Failed to load configured GCloud credentials"); an
unreadable file carries the ``OSError``'s errno. A wrong key is only found
out by the server, as a ``403`` on the first request.
"""

from __future__ import annotations

import errno
import hashlib
import json
import threading
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from xrdsec.rsa import RSAPrivateKey, load_private_key

from ...errors import GError
from ._client import Body, Target

if TYPE_CHECKING:
    from ...options import Options

__all__ = ["GCloudKeys", "GCloudSigner", "KeyCache", "is_gcloud", "load_keys"]

ALGORITHM = "GOOG4-RSA-SHA256"
#: How long a signed URL stays valid.
EXPIRES = 3600


def is_gcloud(scheme: str) -> bool:
    """Whether ``scheme`` is GCS (``gcloud``/``gclouds``, any ``+3rd`` suffix ignored)."""
    return scheme.partition("+")[0] in ("gcloud", "gclouds")


@dataclass(frozen=True)
class GCloudKeys:
    """A service account: its e-mail (the credential's name) and its RSA private key."""

    client_email: str
    key: RSAPrivateKey

    def __repr__(self) -> str:
        """The account's e-mail only: the key never reaches a log."""
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
    """The configured service account, parsed once per distinct configuration.

    Loading a PEM key is milliseconds of work and would otherwise happen on
    every request. The cache is keyed by the option *values* (the file name
    or the inline JSON), so a context that changes its configuration gets
    the new key; a file whose contents change under the same name does not,
    until the plugin is made anew. One per plugin, shared by its threads.
    """

    def __init__(self) -> None:
        """An empty cache; nothing is read until :meth:`get`."""
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], GCloudKeys] = {}

    def get(self, options: Options) -> GCloudKeys | None:
        """The keys ``[GCLOUD]`` configures, or ``None`` for unsigned access.

        ``JSON_AUTH_FILE`` wins over ``JSON_AUTH_STRING`` when both are
        set. Two threads missing the cache at once both parse the
        key; the lock is not held while reading a file, and the second
        result simply replaces an equal first.
        """
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
    """The ISO 8601 basic UTC timestamp V4 signing uses (``20240101T000000Z``)."""
    return (when or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")


def _quote(value: str) -> str:
    """RFC 3986 percent-encoding of a query name or value; ``/`` is encoded too."""
    return urllib.parse.quote(value, safe="")


class GCloudSigner:
    """Turns requests into V4 signed URLs for one service account.

    Stateless apart from the keys, so one signer serves every thread. Each
    request is signed afresh at the moment it is sent, so a URL is never
    reused near its expiry.
    """

    def __init__(self, keys: GCloudKeys, *, expires: int = EXPIRES) -> None:
        """Sign as ``keys``, each URL valid for ``expires`` seconds from signing."""
        self.keys = keys
        self.expires = expires

    def signed_path(self, method: str, target: Target, when: datetime | None = None) -> str:
        """``target.path`` with the ``X-Goog-*`` query that authorises ``method`` on it."""
        stamp = _stamp(when)
        # ``auto`` is the region GCS accepts for every bucket.
        scope = f"{stamp[:8]}/auto/storage/goog4_request"
        # The URL's own query (``?prefix=...`` for a listing) is signed along
        # with the X-Goog-* fields: every query parameter is covered.
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
        # The canonical headers block ends with its own newline, hence the
        # ``\n`` after the host line and the blank line it makes.
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
        """``target`` with the signature in its query; called again on each redirect hop."""
        return replace(target, path=self.signed_path(method, target))

    def sign(
        self, method: str, target: Target, headers: Mapping[str, str], body: Body | None
    ) -> dict[str, str]:
        """No headers: the authorisation is in the URL :meth:`target` made."""
        return {}

    def presign(self, method: str, url: str, expires: int = EXPIRES) -> str:
        """``url`` as a V4 signed URL, for a third-party copy's far side.

        ``expires`` is clamped to what GCS accepts: at least one second, at
        most seven days (604 800 s); a longer request would be refused by
        the server when used, long after the copy was set up.
        """
        target = Target.of(url, s3=True)
        signer = GCloudSigner(self.keys, expires=min(max(expires, 1), 604800))
        return f"{target.base}{signer.signed_path(method, target)}"
