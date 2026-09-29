"""gfal2's configuration: groups of keys, read the way GLib reads a key file.

gfal2 keeps every tunable in a ``GKeyFile`` loaded from ``/etc/gfal2.d/*.conf``
and exposes it through ``get_opt_*``/``set_opt_*``. Callers depend on the
details - FTS sets ``[HTTP PLUGIN] DEFAULT_COPY_MODE``, gfal2-util reads
``[SRM PLUGIN] TURL_PROTOCOLS`` as a list - so this reproduces them: the same
stock defaults, the same ``;``-separated lists, the same boolean spellings,
and the same GLib error codes (3 for a missing key, 4 for a missing group,
5 for a value that will not parse) in the ``GError`` it raises.

The stock defaults are built in, so a machine with no gfal2 installed
behaves like one with a fresh install. ``$GFAL_CONFIG_DIR`` (or, when that is
unset, an existing ``/etc/gfal2.d``) is layered on top, so a site's tuning
applies to this client exactly as it does to the C one.
"""

from __future__ import annotations

import glob
import os
import threading
from collections.abc import Iterable, Mapping

from .errors import GError

__all__ = [
    "Options",
    "DEFAULTS",
    "KEY_NOT_FOUND",
    "GROUP_NOT_FOUND",
    "INVALID_VALUE",
    "parse_ini",
]

#: ``G_KEY_FILE_ERROR_*`` values, which gfal2 passes through as ``code``.
KEY_NOT_FOUND = 3
GROUP_NOT_FOUND = 4
INVALID_VALUE = 5
#: ``G_KEY_FILE_ERROR_PARSE`` - a line that is not a group, a key or a comment.
PARSE_ERROR = 1

#: The configuration a stock gfal2 2.23 installation ships with.
DEFAULTS = """
[CORE]
RESOLVE_DNS=false
NAMESPACE_TIMEOUT=300
CHECKSUM_TIMEOUT=1800
COPY_BUFFERSIZE=4194304
COPY_DIRECT_IO=false
FORMAT_ADLER32_CHECKSUM=true

[BDII]
ENABLED=true
LCG_GFAL_INFOSYS=lcg-bdii.cern.ch:2170
CACHE_FILE=/var/lib/fts3/bdii_cache.xml

[GRIDFTP PLUGIN]
GRIDFTP_V2=true
SESSION_REUSE=true
RD_NB_STREAM=0
COPY_CHECKSUM_TYPE=ADLER32
DCAU=false
IPV6=false
SPAS=false
PERF_MARKER_TIMEOUT=360
DELAY_PASSV=true
ENABLE_UDT=false
ENABLE_PASV_PLUGIN=false

[HTTP PLUGIN]
ENABLE_REMOTE_COPY=true
ENABLE_STREAM_COPY=true
ENABLE_FALLBACK_TPC_COPY=true
DEFAULT_COPY_MODE=3rd pull
INSECURE=false
METALINK=false
LOG_LEVEL=0
LOG_SENSITIVE=false
LOG_CONTENT=false
KEEP_ALIVE=true
RETRIEVE_BEARER_TOKEN=true

[MOCK PLUGIN]
MAX_TRANSFER_TIME=5
MIN_TRANSFER_TIME=5
SIGNALS=0

[SRM PLUGIN]
CONN_TIMEOUT=60
REQUEST_LIFETIME=3600
COPY_CHECKSUM_TYPE=ADLER32
TURL_PROTOCOLS=gsiftp;rfio;gsidcap;dcap;kdcap
TURL_3RD_PARTY_PROTOCOLS=gsiftp;https;root
KEEP_ALIVE=true
COPY_FAIL_NEARLINE=false
XATTR_FAIL_NEARLINE=false

[XROOTD PLUGIN]
COPY_CHECKSUM_TYPE=ADLER32
NORMALIZE_PATH=true
"""

_TRUE = ("true", "1")
_FALSE = ("false", "0")


def parse_ini(text: str, source: str = "<string>") -> dict[str, dict[str, str]]:
    """Parse key-file text into ``{group: {key: raw value}}``.

    Comments start with ``#`` (``;`` is a list separator in values, not a
    comment, exactly as in GLib). A key before any group, or a line that is
    neither, is a parse error naming the file and line.
    """
    groups: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = groups.setdefault(line[1:-1].strip(), {})
            continue
        key, sep, value = line.partition("=")
        if not sep or current is None or not key.strip():
            raise GError(f"Key file {source} line {number} is invalid: {raw!r}", PARSE_ERROR)
        current[key.strip()] = value.strip()
    return groups


class Options:
    """A thread-safe key file with gfal2's accessors.

    >>> opts = Options()
    >>> opts.get_integer("CORE", "NAMESPACE_TIMEOUT")
    300
    """

    def __init__(self, *, load_system: bool = True) -> None:
        self._lock = threading.RLock()
        self._groups: dict[str, dict[str, str]] = {}
        self.merge(parse_ini(DEFAULTS, "<defaults>"))
        if load_system:
            for path in self.system_files():
                self.load_file(path)

    @staticmethod
    def system_files(environ: Mapping[str, str] | None = None) -> list[str]:
        """The ``*.conf`` files gfal2 itself would read, in load order."""
        env = os.environ if environ is None else environ
        directory = env.get("GFAL_CONFIG_DIR") or "/etc/gfal2.d"
        return sorted(glob.glob(os.path.join(directory, "*.conf")))

    # -- bulk ----------------------------------------------------------------

    def merge(self, groups: Mapping[str, Mapping[str, str]]) -> None:
        """Layer ``groups`` over what is already set, key by key."""
        with self._lock:
            for group, keys in groups.items():
                self._groups.setdefault(group, {}).update(keys)

    def load_file(self, path: str) -> None:
        """Merge one ``.ini``-formatted file (``load_opts_from_file``)."""
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            code = exc.errno if exc.errno is not None else 0
            raise GError(f"Could not load configuration file {path}: {exc.strerror}", code) from exc
        self.merge(parse_ini(text, path))

    def groups(self) -> list[str]:
        with self._lock:
            return list(self._groups)

    def keys(self, group: str) -> list[str]:
        with self._lock:
            return list(self._require_group(group))

    def snapshot(self) -> dict[str, dict[str, str]]:
        """A deep copy, for a context that wants to fork its settings."""
        with self._lock:
            return {group: dict(keys) for group, keys in self._groups.items()}

    # -- raw access ------------------------------------------------------------

    def _require_group(self, group: str) -> dict[str, str]:
        found = self._groups.get(group)
        if found is None:
            raise GError(f"Key file does not have group “{group}”", GROUP_NOT_FOUND)
        return found

    def _raw(self, group: str, key: str) -> str:
        with self._lock:
            keys = self._require_group(group)
            if key not in keys:
                raise GError(
                    f"Key file does not have key “{key}” in group “{group}”", KEY_NOT_FOUND
                )
            return keys[key]

    def has(self, group: str, key: str) -> bool:
        with self._lock:
            return key in self._groups.get(group, {})

    def remove(self, group: str, key: str) -> bool:
        with self._lock:
            self._raw(group, key)
            del self._groups[group][key]
            return True

    def _set(self, group: str, key: str, value: str) -> None:
        with self._lock:
            self._groups.setdefault(group, {})[key] = value

    # -- typed accessors -------------------------------------------------------

    def get_string(self, group: str, key: str) -> str:
        return self._raw(group, key)

    def set_string(self, group: str, key: str, value: str) -> None:
        self._set(group, key, str(value))

    def get_integer(self, group: str, key: str) -> int:
        raw = self._raw(group, key)
        try:
            return int(raw.strip())
        except ValueError:
            raise GError(
                f"Key file contains key “{key}” in group “{group}” which has a value "
                "that cannot be interpreted.",
                INVALID_VALUE,
            ) from None

    def set_integer(self, group: str, key: str, value: int) -> None:
        self._set(group, key, str(int(value)))

    def get_boolean(self, group: str, key: str) -> bool:
        raw = self._raw(group, key).strip().lower()
        if raw in _TRUE:
            return True
        if raw in _FALSE:
            return False
        raise GError(
            f"Key file contains key “{key}” which has a value that cannot be interpreted.",
            INVALID_VALUE,
        )

    def set_boolean(self, group: str, key: str, value: bool) -> None:
        self._set(group, key, "true" if value else "false")

    def get_string_list(self, group: str, key: str) -> list[str]:
        raw = self._raw(group, key)
        parts = raw.split(";")  # never empty: splitting "" gives [""]
        if parts[-1] == "":
            parts.pop()
        return parts

    def set_string_list(self, group: str, key: str, values: Iterable[str]) -> None:
        self._set(group, key, "".join(f"{value};" for value in values))

    # -- defaulted reads for plugin code -----------------------------------------

    def string(self, group: str, key: str, default: str = "") -> str:
        """``get_string`` that answers ``default`` instead of raising."""
        try:
            return self.get_string(group, key)
        except GError:
            return default

    def integer(self, group: str, key: str, default: int = 0) -> int:
        try:
            return self.get_integer(group, key)
        except GError:
            return default

    def boolean(self, group: str, key: str, default: bool = False) -> bool:
        try:
            return self.get_boolean(group, key)
        except GError:
            return default

    def string_list(self, group: str, key: str, default: list[str] | None = None) -> list[str]:
        try:
            return self.get_string_list(group, key)
        except GError:
            return list(default or [])

    def timeout(self, group: str, key: str = "OPERATION_TIMEOUT") -> int:
        """A plugin's operation timeout, falling back to the core namespace one."""
        if self.has(group, key):
            return self.integer(group, key, 300)
        return self.integer("CORE", "NAMESPACE_TIMEOUT", 300)
