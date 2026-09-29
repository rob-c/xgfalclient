"""gfal2's configuration: groups of keys, read the way GLib reads a key file.

gfal2 keeps every tunable in a ``GKeyFile`` loaded from ``/etc/gfal2.d/*.conf``
and exposes it through ``get_opt_*``/``set_opt_*``. Callers depend on the
details - FTS sets ``[HTTP PLUGIN] DEFAULT_COPY_MODE``, gfal2-util reads
``[SRM PLUGIN] TURL_PROTOCOLS`` as a list - so this reproduces them: the same
stock defaults, the same ``;``-separated lists, the same boolean spellings,
and the same GLib error codes (3 for a missing key, 4 for a missing group,
5 for a value that will not parse) in the ``GError`` it raises.

Values parse as GLib parses them: a boolean is exactly ``true``/``false``/
``1``/``0`` (trailing blanks allowed, case significant), an integer is
decimal digits with an optional sign within the C ``int`` range. A group
with no keys in a file is not created, since gfal2 merges key by key. A file
that will not load fails with ``Error while loading configuration file
<path>: <GLib's text>`` and GLib's code (``G_FILE_ERROR_*`` for the file,
``G_KEY_FILE_ERROR_*`` for its contents).

The stock defaults are built in, so a machine with no gfal2 installed
behaves like one with a fresh install. ``$GFAL_CONFIG_DIR`` (or, when that is
unset, an existing ``/etc/gfal2.d``) is layered on top, so a site's tuning
applies to this client exactly as it does to the C one. (gfal2 refuses to
start with a missing or partial configuration directory; this deliberately
does not.)
"""

from __future__ import annotations

import errno
import os
import re
import stat
import threading
from collections.abc import Iterable, Mapping

from . import _log
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

#: ``g_file_error_from_errno``: the ``GFileError`` code a failed open reports.
_FILE_ERRORS = {
    errno.EEXIST: 0,
    errno.EISDIR: 1,
    errno.EACCES: 2,
    errno.ENAMETOOLONG: 3,
    errno.ENOENT: 4,
    errno.ENOTDIR: 5,
    errno.ENXIO: 6,
    errno.ENODEV: 7,
    errno.EROFS: 8,
    errno.ETXTBSY: 9,
    errno.EFAULT: 10,
    errno.ELOOP: 11,
    errno.ENOSPC: 12,
    errno.ENOMEM: 13,
    errno.EMFILE: 14,
    errno.ENFILE: 15,
    errno.EBADF: 16,
    errno.EINVAL: 17,
    errno.EPIPE: 18,
    errno.EAGAIN: 19,
    errno.EINTR: 20,
    errno.EIO: 21,
    errno.EPERM: 22,
    errno.ENOSYS: 23,
}
#: ``G_FILE_ERROR_FAILED``, for anything else.
_FILE_FAILED = 24

#: What ``g_key_file_get_integer`` accepts: ``strtol`` skips leading blanks,
#: and nothing may follow the digits.
_INTEGER = re.compile(r"[ \t\n\v\f\r]*[+-]?[0-9]+\Z")
_INT_MIN, _INT_MAX = -(2**31), 2**31 - 1
_BLANKS = " \t\n\v\f\r"

#: The configuration a stock gfal2 2.23 installation ships with.
#: gfal2's default configuration directory, spelt as it logs it (with the slash).
DEFAULT_CONFIG_DIR = "/etc/gfal2.d/"


def is_config_name(name: str) -> bool:
    """gfal2's ``is_config_dir``: the first ``.conf`` in the name ends it."""
    at = name.find(".conf")
    return at >= 0 and at + len(".conf") == len(name)


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
    neither, is an error worded and numbered as GLib's; the caller names
    the file (``source`` is kept for callers that pass it).
    """
    groups: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = groups.setdefault(line[1:-1].strip(), {})
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            raise GError(
                f"Key file contains line “{raw}” which is not a key-value pair, group, or comment",
                PARSE_ERROR,
            )
        if current is None:
            raise GError("Key file does not start with a group", GROUP_NOT_FOUND)
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
            for path in self.system_files(announce=True):
                _log.LOGGER.debug(" try to load configuration file %s ...", path)
                self.load_file(path)

    @staticmethod
    def system_files(environ: Mapping[str, str] | None = None, announce: bool = False) -> list[str]:
        """The ``*.conf`` files gfal2 itself would read, in load order.

        That order is the directory's (``readdir``'s), not sorted: a key set
        in two files takes the value of the one read last. With ``announce``
        the directory chosen is logged in gfal2's words.
        """
        env = os.environ if environ is None else environ
        configured = env.get("GFAL_CONFIG_DIR")
        if configured:
            directory = configured
            message = " GFAL_CONFIG_DIR env var found, try to load configuration from %s"
        else:
            directory = DEFAULT_CONFIG_DIR
            message = (
                " no GFAL_CONFIG_DIR env var found, "
                "try to load configuration from default directory %s"
            )
        if announce:
            _log.LOGGER.debug(message, directory)
        try:
            names = os.listdir(directory)
        except OSError:  # gfal2 fails outright; the built-in defaults stand in
            return []
        return [f"{directory}/{name}" for name in names if is_config_name(name)]

    # -- bulk ----------------------------------------------------------------

    def merge(self, groups: Mapping[str, Mapping[str, str]]) -> None:
        """Layer ``groups`` over what is already set, key by key (so a group
        without keys is not created)."""
        with self._lock:
            for group, keys in groups.items():
                if keys:
                    self._groups.setdefault(group, {}).update(keys)

    def load_file(self, path: str) -> None:
        """Merge one ``.ini``-formatted file (``load_opts_from_file``), all or nothing."""
        try:
            self.merge(parse_ini(_read_key_file(path), path))
        except GError as exc:
            raise GError(
                f"Error while loading configuration file {path}: {exc.message}", exc.code
            ) from exc

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
        if _INTEGER.match(raw) and _INT_MIN <= int(raw) <= _INT_MAX:
            return int(raw)
        raise GError(
            f"Key file contains key “{key}” in group “{group}” which has a value "
            "that cannot be interpreted.",
            INVALID_VALUE,
        )

    def set_integer(self, group: str, key: str, value: int) -> None:
        self._set(group, key, str(int(value)))

    def get_boolean(self, group: str, key: str) -> bool:
        raw = self._raw(group, key).rstrip(_BLANKS)
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


def _read_key_file(path: str) -> str:
    """The text of ``path``, failing as ``g_key_file_load_from_file`` does."""
    try:
        with open(path, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise GError("Not a regular file", PARSE_ERROR)
            data = handle.read()
    except OSError as exc:
        if exc.errno == errno.EISDIR:  # GLib opens a directory, then finds it irregular
            raise GError("Not a regular file", PARSE_ERROR) from exc
        if exc.errno is None:
            raise GError(str(exc), _FILE_FAILED) from exc
        code = _FILE_ERRORS.get(exc.errno, _FILE_FAILED)
        raise GError(os.strerror(exc.errno), code) from exc
    return data.decode("utf-8", "surrogateescape")
