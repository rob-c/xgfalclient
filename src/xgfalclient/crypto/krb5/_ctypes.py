"""GSS-API over ``ctypes``: the system's own Kerberos library, no extension.

The point of going through the platform library rather than a pip package
is credentials: ``libgssapi_krb5`` reads whatever the host's ``krb5.conf``
says the default credential cache is - KCM through sssd on EL9, ``FILE:``,
``KEYRING:``, or the macOS ``API:`` cache - and honours ``KRB5CCNAME`` and
``KRB5_KTNAME`` exactly as ``kinit`` and every other client on the machine
do. Nothing here parses a cache or builds a Kerberos message.

The RFC 2744 C binding is the same in MIT krb5 and Heimdal (Apple's
``GSS.framework`` included), so one set of signatures serves both. Two
details differ and are handled here:

* On 32-bit and x86-64 macOS the headers wrap every GSS struct in
  ``#pragma pack(push,2)``, which moves ``gss_OID_desc.elements`` from
  offset 8 to 4 (:func:`packing`).
* Choosing a credential cache or keytab per call is
  ``gss_acquire_cred_from`` in MIT; Heimdal lacks it, and the process-wide
  ``gss_krb5_ccache_name`` and ``gsskrb5_register_acceptor_identity`` stand
  in, under a lock.

The mechanism and name-type OIDs are built here from their DER bytes rather
than read from exported variables, whose names differ between the two.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
import sys
import threading
import types
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from ._base import ACCEPT, HOSTBASED, INITIATE, Backend, Mechanism, Target
from ._status import (
    CONTINUE_NEEDED,
    SUPPLEMENTARY_MASK,
    KerberosError,
    describe,
    is_error,
)

__all__ = [
    "CtypesBackend",
    "CtypesMechanism",
    "Library",
    "candidates",
    "load",
    "packing",
    "LIBRARY_ENV",
]

#: Names a GSS-API library to use instead of searching for one.
LIBRARY_ENV = "XGFAL_GSSAPI_LIBRARY"


def packing(system: str, machine: str) -> dict[str, Any]:
    """The ``Structure`` attributes that reproduce the headers' packing."""
    if system == "darwin" and machine in ("x86_64", "i386", "ppc", "ppc64"):
        # ``_layout_`` keeps Python 3.14+ from warning that ``_pack_`` alone
        # is ambiguous; older versions ignore it.
        return {"_pack_": 2, "_layout_": "ms"}
    return {}


_PACKING = packing(sys.platform, platform.machine())


def _struct(name: str, fields: list[tuple[str, Any]]) -> Any:
    return type(name, (ctypes.Structure,), {"_fields_": fields, **_PACKING})


Buffer = _struct("gss_buffer_desc", [("length", ctypes.c_size_t), ("value", ctypes.c_void_p)])
OID = _struct("gss_OID_desc", [("length", ctypes.c_uint32), ("elements", ctypes.c_void_p)])
OIDSet = _struct(
    "gss_OID_set_desc", [("count", ctypes.c_size_t), ("elements", ctypes.POINTER(OID))]
)
KeyValue = _struct(
    "gss_key_value_element_desc", [("key", ctypes.c_char_p), ("value", ctypes.c_char_p)]
)
KeyValueSet = _struct(
    "gss_key_value_set_desc",
    [("count", ctypes.c_uint32), ("elements", ctypes.POINTER(KeyValue))],
)


def _oid(der: bytes) -> tuple[Any, Any]:
    raw = ctypes.create_string_buffer(der, len(der))
    return OID(len(der), ctypes.cast(raw, ctypes.c_void_p)), raw


#: 1.2.840.113554.1.2.2 - Kerberos 5.
KRB5_MECH, _KRB5_RAW = _oid(bytes.fromhex("2a864886f712010202"))
#: 1.2.840.113554.1.2.1.4 - ``GSS_C_NT_HOSTBASED_SERVICE``.
NT_HOSTBASED, _NT_HOSTBASED_RAW = _oid(bytes.fromhex("2a864886f71201020104"))
#: 1.2.840.113554.1.2.2.1 - ``GSS_KRB5_NT_PRINCIPAL_NAME``.
NT_PRINCIPAL, _NT_PRINCIPAL_RAW = _oid(bytes.fromhex("2a864886f71201020201"))
KRB5_MECHS = OIDSet(1, ctypes.pointer(KRB5_MECH))

GSS_C_GSS_CODE = 1
GSS_C_MECH_CODE = 2

_U32 = ctypes.c_uint32
_P = ctypes.c_void_p
_PU32 = ctypes.POINTER(ctypes.c_uint32)
_PP = ctypes.POINTER(ctypes.c_void_p)
_PBUF = ctypes.POINTER(Buffer)
_POID = ctypes.POINTER(OID)
_PPOID = ctypes.POINTER(_POID)
_POIDSET = ctypes.POINTER(OIDSet)
_PINT = ctypes.POINTER(ctypes.c_int)

#: Every function this module calls, with its argument types.
SIGNATURES: dict[str, list[Any]] = {
    "gss_import_name": [_PU32, _PBUF, _POID, _PP],
    "gss_display_name": [_PU32, _P, _PBUF, _PPOID],
    "gss_release_name": [_PU32, _PP],
    "gss_release_buffer": [_PU32, _PBUF],
    "gss_display_status": [_PU32, _U32, ctypes.c_int, _POID, _PU32, _PBUF],
    "gss_acquire_cred": [_PU32, _P, _U32, _POIDSET, ctypes.c_int, _PP, _P, _PU32],
    "gss_release_cred": [_PU32, _PP],
    "gss_init_sec_context": [
        _PU32,
        _P,
        _PP,
        _P,
        _POID,
        _U32,
        _U32,
        _P,
        _PBUF,
        _PPOID,
        _PBUF,
        _PU32,
        _PU32,
    ],
    "gss_accept_sec_context": [
        _PU32,
        _PP,
        _P,
        _PBUF,
        _P,
        _PP,
        _PPOID,
        _PBUF,
        _PU32,
        _PU32,
        _PP,
    ],
    "gss_delete_sec_context": [_PU32, _PP, _PBUF],
    "gss_inquire_context": [_PU32, _P, _PP, _PP, _PU32, _PPOID, _PU32, _PINT, _PINT],
    "gss_wrap": [_PU32, _P, ctypes.c_int, _U32, _PBUF, _PINT, _PBUF],
    "gss_unwrap": [_PU32, _P, _PBUF, _PBUF, _PINT, _PU32],
    "gss_get_mic": [_PU32, _P, _U32, _PBUF, _PBUF],
    "gss_verify_mic": [_PU32, _P, _PBUF, _PBUF, _PU32],
}

#: Present in some libraries only; each has a fallback.
OPTIONAL: dict[str, list[Any]] = {
    "gss_acquire_cred_from": [
        _PU32,
        _P,
        _U32,
        _POIDSET,
        ctypes.c_int,
        ctypes.POINTER(KeyValueSet),
        _PP,
        _P,
        _PU32,
    ],
    "gss_krb5_ccache_name": [_PU32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)],
    "gsskrb5_register_acceptor_identity": [ctypes.c_char_p],
    "krb5_gss_register_acceptor_identity": [ctypes.c_char_p],
}

#: Serialises the process-wide fallbacks (ccache name, acceptor identity).
_GLOBAL = threading.Lock()


def candidates(
    system: str, find: Callable[[str], str | None] = ctypes.util.find_library
) -> Iterator[str]:
    """Where to look for a GSS-API library, best first, without repeats.

    On macOS the system ``GSS.framework`` comes first: it is the library
    that can read the tickets Apple's ``kinit`` stores. Apple's
    ``libgssapi_krb5.dylib`` is a compatibility shim over the same code;
    Homebrew's MIT build follows. Elsewhere the MIT soname, then Heimdal's.
    ``find_library`` (which may run ``ldconfig``) is asked only when those
    fail, which is why this is a generator.
    """
    seen: set[str] = set()

    def fresh(paths: list[str]) -> Iterator[str]:
        for path in paths:
            if path and path not in seen:
                seen.add(path)
                yield path

    yield from fresh([os.environ.get(LIBRARY_ENV, "")])
    if system == "darwin":
        yield from fresh(
            [
                "/System/Library/Frameworks/GSS.framework/GSS",
                "/usr/lib/libgssapi_krb5.dylib",
                "/opt/homebrew/opt/krb5/lib/libgssapi_krb5.dylib",
                "/usr/local/opt/krb5/lib/libgssapi_krb5.dylib",
            ]
        )
    else:
        yield from fresh(["libgssapi_krb5.so.2", "libgssapi.so.3"])
    for stem in ("gssapi_krb5", "gssapi"):
        yield from fresh([find(stem) or ""])


class Library:
    """A loaded GSS-API library with its signatures declared.

    The handle is shared by every context; the library is thread-safe for
    distinct contexts, which is all that is ever asked of it.
    """

    def __init__(self, handle: Any, path: str) -> None:
        self.path = path
        self.flavour = "heimdal" if hasattr(handle, "gsskrb5_register_acceptor_identity") else "mit"
        #: The required functions, as attributes (``lib.api.gss_wrap``).
        self.api = types.SimpleNamespace(
            **{name: self._declare(handle, name, argtypes) for name, argtypes in SIGNATURES.items()}
        )
        self.optional: dict[str, Any] = {
            name: self._declare(handle, name, argtypes)
            for name, argtypes in OPTIONAL.items()
            if hasattr(handle, name)
        }

    @staticmethod
    def _declare(handle: Any, name: str, argtypes: list[Any]) -> Any:
        function = getattr(handle, name)
        function.argtypes = argtypes
        function.restype = ctypes.c_uint32
        return function

    # -- buffers and statuses ---------------------------------------------------------------

    def take(self, buffer: Any) -> bytes:
        """Copy an output buffer into ``bytes`` and give it back to the library."""
        if not buffer.value:
            return b""
        data = ctypes.string_at(buffer.value, buffer.length)
        self.api.gss_release_buffer(ctypes.c_uint32(), buffer)
        return data

    def display(self, status: int, kind: int) -> list[str]:
        """``gss_display_status``, every message in the chain."""
        messages: list[str] = []
        context = ctypes.c_uint32(0)
        for _ in range(8):  # a broken library must not loop us forever
            minor = ctypes.c_uint32()
            buffer = Buffer()
            major = self.api.gss_display_status(minor, status, kind, KRB5_MECH, context, buffer)
            if is_error(major):
                break
            text = self.take(buffer).decode("utf-8", "replace").strip()
            if text:
                messages.append(text)
            if not context.value:
                break
        return messages

    def error(
        self, what: str, major: int, minor: int, *, protection: bool = False, token: bytes = b""
    ) -> KerberosError:
        """The ``KerberosError`` for a failed call, in the library's words."""
        texts = self.display(major & ~SUPPLEMENTARY_MASK or major, GSS_C_GSS_CODE)
        details = self.display(minor, GSS_C_MECH_CODE) if minor and is_error(major) else []
        return describe(what, major, minor, texts, details, protection=protection, token=token)

    def check(self, what: str, major: int, minor: Any, *, protection: bool = False) -> None:
        if is_error(major) or (protection and major & SUPPLEMENTARY_MASK):
            raise self.error(what, major, minor.value, protection=protection)

    # -- names and credentials -------------------------------------------------------------

    def import_name(self, target: Target) -> Any:
        name = ctypes.c_void_p()
        minor = ctypes.c_uint32()
        text = target.name.encode("utf-8")
        buffer, keep = _input(text)
        kind = NT_HOSTBASED if target.kind == HOSTBASED else NT_PRINCIPAL
        major = self.api.gss_import_name(minor, buffer, kind, name)
        del keep
        self.check(f"importing the Kerberos name {target.name!r}", major, minor)
        return name

    def display_name(self, name: Any) -> str:
        minor = ctypes.c_uint32()
        buffer = Buffer()
        major = self.api.gss_display_name(minor, name, buffer, None)
        self.check("displaying a Kerberos name", major, minor)
        return self.take(buffer).decode("utf-8", "replace")

    def release_name(self, name: Any) -> None:
        if name.value:
            self.api.gss_release_name(ctypes.c_uint32(), name)

    def release_cred(self, cred: Any) -> None:
        if cred.value:
            self.api.gss_release_cred(ctypes.c_uint32(), cred)

    def acquire(self, name: Any, usage: int, store: dict[str, str]) -> Any:
        """A credential for ``usage``, optionally from a named cache or keytab."""
        cred = ctypes.c_void_p()
        minor = ctypes.c_uint32()
        what = "acquiring Kerberos credentials"
        from_store = self.optional.get("gss_acquire_cred_from")
        if store and from_store is not None:
            pairs = [(key.encode(), value.encode()) for key, value in store.items()]
            elements = (KeyValue * len(pairs))(*(KeyValue(k, v) for k, v in pairs))
            major = from_store(
                minor,
                name,
                0,
                KRB5_MECHS,
                usage,
                KeyValueSet(len(pairs), elements),
                cred,
                None,
                None,
            )
        elif store:
            with _GLOBAL:
                major = self._acquire_legacy(name, usage, store, cred, minor)
        else:
            major = self.api.gss_acquire_cred(minor, name, 0, KRB5_MECHS, usage, cred, None, None)
        self.check(what, major, minor)
        return cred

    def _acquire_legacy(
        self, name: Any, usage: int, store: dict[str, str], cred: Any, minor: Any
    ) -> int:
        """Heimdal: point the process-wide setting at the store, acquire, put it back."""
        if "keytab" in store:
            register = self.optional.get("gsskrb5_register_acceptor_identity") or self.optional.get(
                "krb5_gss_register_acceptor_identity"
            )
            if register is None:
                raise KerberosError(
                    f"{self.path} cannot use a keytab other than the default (set KRB5_KTNAME)",
                    errno.EOPNOTSUPP,
                )
            register(store["keytab"].encode())
            return int(
                self.api.gss_acquire_cred(minor, name, 0, KRB5_MECHS, usage, cred, None, None)
            )
        select = self.optional.get("gss_krb5_ccache_name")
        if select is None:
            raise KerberosError(
                f"{self.path} cannot use a credential cache other than the default "
                "(set KRB5CCNAME)",
                errno.EOPNOTSUPP,
            )
        previous = ctypes.c_char_p()
        major = select(minor, store["ccache"].encode(), previous)
        self.check("selecting the credential cache", major, minor)
        saved = previous.value
        try:
            return int(
                self.api.gss_acquire_cred(minor, name, 0, KRB5_MECHS, usage, cred, None, None)
            )
        finally:
            select(ctypes.c_uint32(), saved, None)


def _input(data: bytes) -> tuple[Any, Any]:
    """An input ``gss_buffer_desc`` over ``data`` (no copy) and what keeps it alive."""
    pointer = ctypes.c_char_p(data)
    return Buffer(len(data), ctypes.cast(pointer, ctypes.c_void_p)), pointer


class CtypesMechanism(Mechanism):
    """One ``gss_ctx_id_t`` and the name and credential it was built with."""

    def __init__(
        self, library: Library, *, initiate: bool, target: Any, cred: Any, flags: int
    ) -> None:
        self.lib = library
        self.initiate = initiate
        self.target = target
        self.cred = cred
        self.flags = flags
        self.handle = ctypes.c_void_p()
        self.returned = 0
        self.complete = False

    def step(self, token: bytes) -> bytes:
        lib = self.lib
        minor = ctypes.c_uint32()
        output = Buffer()
        returned = ctypes.c_uint32()
        buffer, keep = _input(token) if token else (None, None)
        if self.initiate:
            major = lib.api.gss_init_sec_context(
                minor,
                self.cred,
                self.handle,
                self.target,
                KRB5_MECH,
                self.flags,
                0,
                None,
                buffer,
                None,
                output,
                returned,
                None,
            )
            what = "Kerberos authentication (gss_init_sec_context)"
        else:
            major = lib.api.gss_accept_sec_context(
                minor,
                self.handle,
                self.cred,
                buffer,
                None,
                None,
                None,
                output,
                returned,
                None,
                None,
            )
            what = "Kerberos authentication (gss_accept_sec_context)"
        del keep
        out = lib.take(output)
        if is_error(major):
            raise lib.error(what, major, minor.value, token=out)
        self.returned = returned.value
        self.complete = not major & CONTINUE_NEEDED
        return out

    def wrap(self, data: bytes, confidential: bool) -> tuple[bytes, bool]:
        minor = ctypes.c_uint32()
        state = ctypes.c_int(0)
        output = Buffer()
        buffer, keep = _input(data)
        major = self.lib.api.gss_wrap(
            minor, self.handle, int(confidential), 0, buffer, state, output
        )
        del keep
        out = self.lib.take(output)
        self.lib.check("gss_wrap", major, minor, protection=True)
        return out, bool(state.value)

    def unwrap(self, token: bytes) -> tuple[bytes, bool]:
        minor = ctypes.c_uint32()
        state = ctypes.c_int(0)
        output = Buffer()
        buffer, keep = _input(token)
        major = self.lib.api.gss_unwrap(minor, self.handle, buffer, output, state, None)
        del keep
        out = self.lib.take(output)
        self.lib.check("gss_unwrap", major, minor, protection=True)
        return out, bool(state.value)

    def get_mic(self, data: bytes) -> bytes:
        minor = ctypes.c_uint32()
        output = Buffer()
        buffer, keep = _input(data)
        major = self.lib.api.gss_get_mic(minor, self.handle, 0, buffer, output)
        del keep
        out = self.lib.take(output)
        self.lib.check("gss_get_mic", major, minor, protection=True)
        return out

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        minor = ctypes.c_uint32()
        message, keep_message = _input(data)
        token, keep_token = _input(mic)
        major = self.lib.api.gss_verify_mic(minor, self.handle, message, token, None)
        del keep_message, keep_token
        self.lib.check("gss_verify_mic", major, minor, protection=True)

    def inquire(self) -> tuple[str, str, int]:
        lib = self.lib
        minor = ctypes.c_uint32()
        source = ctypes.c_void_p()
        target = ctypes.c_void_p()
        flags = ctypes.c_uint32()
        major = lib.api.gss_inquire_context(
            minor, self.handle, source, target, None, None, flags, None, None
        )
        try:
            lib.check("gss_inquire_context", major, minor)
            return lib.display_name(source), lib.display_name(target), flags.value
        finally:
            lib.release_name(source)
            lib.release_name(target)

    def close(self) -> None:
        lib = self.lib
        if self.handle.value:
            lib.api.gss_delete_sec_context(ctypes.c_uint32(), self.handle, None)
            self.handle = ctypes.c_void_p()
        if self.target is not None:
            lib.release_name(self.target)
            self.target = None
        if self.cred is not None:
            lib.release_cred(self.cred)
            self.cred = None


class CtypesBackend(Backend):
    """Contexts built on a :class:`Library`."""

    def __init__(self, library: Library) -> None:
        self.library = library
        self.name = f"ctypes-{library.flavour}"

    def initiator(self, target: Target, flags: int, ccache: str | None) -> Mechanism:
        lib = self.library
        name = lib.import_name(target)
        try:
            cred = lib.acquire(None, INITIATE, {"ccache": ccache}) if ccache else None
        except KerberosError:
            lib.release_name(name)
            raise
        return CtypesMechanism(lib, initiate=True, target=name, cred=cred, flags=flags)

    def acceptor(self, name: Target | None, keytab: str | None) -> Mechanism:
        lib = self.library
        imported = lib.import_name(name) if name is not None else None
        try:
            if imported is not None or keytab:
                store = {"keytab": keytab} if keytab else {}
                cred = lib.acquire(imported, ACCEPT, store)
            else:
                cred = None  # GSS_C_NO_CREDENTIAL: any key in the default keytab
        finally:
            if imported is not None:
                lib.release_name(imported)
        return CtypesMechanism(lib, initiate=False, target=None, cred=cred, flags=0)


def load(
    paths: Iterable[str] | None = None, loader: Callable[[str], Any] = ctypes.CDLL
) -> CtypesBackend:
    """The first library in ``paths`` (default :func:`candidates`) that loads.

    Raises ``OSError`` listing why each one was passed over.
    """
    tried: list[str] = []
    for path in candidates(sys.platform) if paths is None else paths:
        try:
            return CtypesBackend(Library(loader(path), path))
        except OSError as exc:
            tried.append(f"{path}: {exc}")
        except AttributeError as exc:
            tried.append(f"{path}: not a GSS-API library ({exc})")
    raise OSError("no GSS-API library found (" + "; ".join(tried or ["nothing to try"]) + ")")
