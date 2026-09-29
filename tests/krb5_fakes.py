"""Stand-ins for a GSS-API library and for the ``gssapi`` package.

:class:`FakeGSS` looks like a ``ctypes.CDLL`` of ``libgssapi_krb5`` to
:mod:`xgfalclient.crypto.krb5._ctypes`: the same function names, each
accepting ``argtypes``/``restype`` assignments, called with the very ctypes
objects the binding passes (a real ``CDLL`` would ``byref`` them). Its
"mechanism" is a toy - tokens are readable strings - but it allocates and
frees buffers, names, credentials and contexts like a real library, so a
test can assert that nothing leaks, and any call can be made to fail with a
chosen major/minor status.

:func:`fake_gssapi_module` is the same idea for python-gssapi.
"""

from __future__ import annotations

import ctypes
import itertools
import types
from collections.abc import Callable
from typing import Any

COMPLETE = 0
CONTINUE = 1
FAILURE = 13 << 16
DEFECTIVE_TOKEN = 9 << 16
BAD_MIC = 6 << 16
NO_CRED = 7 << 16
BAD_NAME = 2 << 16

KRB5_OID = bytes.fromhex("2a864886f712010202")
HOSTBASED_OID = bytes.fromhex("2a864886f71201020104")
PRINCIPAL_OID = bytes.fromhex("2a864886f71201020201")

USER = "user@XGFAL.TEST"


class FakeFunction:
    """A callable that tolerates ``argtypes``/``restype`` like a ctypes function."""

    def __init__(self, name: str, impl: Callable[..., int], calls: list[str]) -> None:
        self.name = name
        self.impl = impl
        self.calls = calls
        self.argtypes: Any = None
        self.restype: Any = None

    def __call__(self, *args: Any) -> int:
        self.calls.append(self.name)
        return self.impl(*args)


REQUIRED = (
    "gss_import_name",
    "gss_display_name",
    "gss_release_name",
    "gss_release_buffer",
    "gss_display_status",
    "gss_acquire_cred",
    "gss_release_cred",
    "gss_init_sec_context",
    "gss_accept_sec_context",
    "gss_delete_sec_context",
    "gss_inquire_context",
    "gss_wrap",
    "gss_unwrap",
    "gss_get_mic",
    "gss_verify_mic",
)


class FakeGSS:
    """A GSS-API library in Python. ``flavour`` picks the optional symbols."""

    def __init__(self, flavour: str = "mit", *, omit: tuple[str, ...] = ()) -> None:
        self.calls: list[str] = []
        self.fail: dict[str, tuple[int, int]] = {}
        self.objects: dict[int, Any] = {}
        self.buffers: dict[int, Any] = {}
        self.ids = itertools.count(0x1000)
        self.no_conf = False
        self.inquire_flags: int | None = None
        self.display_loops = False
        self.display_empty = False
        self.display_fails = False
        self.ccache_name: bytes | None = None
        self.acceptor_identity: bytes | None = None
        names = list(REQUIRED)
        if flavour == "mit":
            names += ["gss_acquire_cred_from", "gss_krb5_ccache_name"]
            names.append("krb5_gss_register_acceptor_identity")
        elif flavour == "heimdal":
            names += ["gss_krb5_ccache_name", "gsskrb5_register_acceptor_identity"]
            names.append("krb5_gss_register_acceptor_identity")
        elif flavour == "old-mit":
            names.append("krb5_gss_register_acceptor_identity")
        for name in names:
            if name not in omit:
                impl = getattr(self, "_" + name)
                setattr(self, name, FakeFunction(name, impl, self.calls))

    # -- plumbing -----------------------------------------------------------------------

    def live(self) -> dict[int, Any]:
        """Everything allocated and not yet released."""
        return {**self.objects, **self.buffers}

    def _new(self, thing: Any) -> int:
        handle = next(self.ids)
        self.objects[handle] = thing
        return handle

    def _out(self, buffer: Any, data: bytes) -> None:
        raw = ctypes.create_string_buffer(data, len(data) or 1)
        buffer.length = len(data)
        buffer.value = ctypes.addressof(raw)
        self.buffers[ctypes.addressof(raw)] = raw

    @staticmethod
    def _in(buffer: Any) -> bytes:
        if buffer is None:
            return b""
        return ctypes.string_at(buffer.value, buffer.length)

    @staticmethod
    def _oid(oid: Any) -> bytes:
        return ctypes.string_at(oid.elements, oid.length)

    def _failed(self, name: str, minor: Any) -> int | None:
        if name in self.fail:
            major, code = self.fail.pop(name)
            minor.value = code
            return major
        return None

    # -- names, buffers, statuses -----------------------------------------------------------

    def _gss_import_name(self, minor: Any, buffer: Any, oid: Any, out: Any) -> int:
        failed = self._failed("gss_import_name", minor)
        if failed is not None:
            return failed
        kind = self._oid(oid)
        text = self._in(buffer).decode()
        if kind == HOSTBASED_OID:
            service, _, host = text.partition("@")
            text = f"{service}/{host or 'localhost'}@XGFAL.TEST"
        else:
            assert kind == PRINCIPAL_OID
        out.value = self._new(("name", text))
        return COMPLETE

    def _gss_display_name(self, minor: Any, name: Any, buffer: Any, kind: Any) -> int:
        failed = self._failed("gss_display_name", minor)
        if failed is not None:
            return failed
        assert kind is None
        self._out(buffer, self.objects[name.value][1].encode())
        return COMPLETE

    def _gss_release_name(self, minor: Any, name: Any) -> int:
        del self.objects[name.value]
        name.value = None
        return COMPLETE

    def _gss_release_buffer(self, minor: Any, buffer: Any) -> int:
        del self.buffers[buffer.value]
        buffer.value = None
        buffer.length = 0
        return COMPLETE

    def _gss_display_status(
        self, minor: Any, status: int, kind: int, mech: Any, context: Any, buffer: Any
    ) -> int:
        assert self._oid(mech) == KRB5_OID
        if self.display_fails:
            return BAD_NAME
        if self.display_empty:
            self._out(buffer, b"")
            return COMPLETE
        word = "major" if kind == 1 else "minor"
        self._out(buffer, f"{word} {status:#x} part {context.value}".encode())
        # Two messages for a major status, one for a minor; or never-ending.
        context.value = 1 if self.display_loops or (kind == 1 and context.value == 0) else 0
        return COMPLETE

    # -- credentials ---------------------------------------------------------------------

    def _acquire(self, name: Any, usage: int, store: dict[str, str], out: Any) -> None:
        text = self.objects[name.value][1] if name is not None and name.value else None
        out.value = self._new(("cred", usage, text, store))

    def _gss_acquire_cred(
        self, minor: Any, name: Any, time: int, mechs: Any, usage: int, out: Any, a: Any, t: Any
    ) -> int:
        failed = self._failed("gss_acquire_cred", minor)
        if failed is not None:
            return failed
        assert mechs.count == 1 and self._oid(mechs.elements[0]) == KRB5_OID
        store: dict[str, str] = {}
        if self.ccache_name is not None:
            store["ccache"] = self.ccache_name.decode()
        if self.acceptor_identity is not None and usage == 2:
            store["keytab"] = self.acceptor_identity.decode()
        self._acquire(name, usage, store, out)
        return COMPLETE

    def _gss_acquire_cred_from(
        self,
        minor: Any,
        name: Any,
        time: int,
        mechs: Any,
        usage: int,
        values: Any,
        out: Any,
        a: Any,
        t: Any,
    ) -> int:
        failed = self._failed("gss_acquire_cred_from", minor)
        if failed is not None:
            return failed
        store = {
            values.elements[i].key.decode(): values.elements[i].value.decode()
            for i in range(values.count)
        }
        self._acquire(name, usage, store, out)
        return COMPLETE

    def _gss_release_cred(self, minor: Any, cred: Any) -> int:
        del self.objects[cred.value]
        cred.value = None
        return COMPLETE

    def _gss_krb5_ccache_name(self, minor: Any, name: Any, previous: Any) -> int:
        failed = self._failed("gss_krb5_ccache_name", minor)
        if failed is not None:
            return failed
        if previous is not None:
            previous.value = self.ccache_name
        self.ccache_name = name
        return COMPLETE

    def _gsskrb5_register_acceptor_identity(self, path: bytes) -> int:
        self.acceptor_identity = path
        return COMPLETE

    _krb5_gss_register_acceptor_identity = _gsskrb5_register_acceptor_identity

    # -- contexts --------------------------------------------------------------------------

    def _gss_init_sec_context(
        self,
        minor: Any,
        cred: Any,
        handle: Any,
        target: Any,
        mech: Any,
        flags: int,
        time: int,
        bindings: Any,
        token: Any,
        actual: Any,
        output: Any,
        returned: Any,
        lifetime: Any,
    ) -> int:
        assert self._oid(mech) == KRB5_OID
        failed = self._failed("gss_init_sec_context", minor)
        if failed is not None:
            self._out(output, b"")
            return failed
        if not handle.value:
            assert token is None
            name = self.objects[target.value][1]
            handle.value = self._new({"target": name, "flags": flags, "initiator": USER})
            self._out(output, f"AP-REQ {name} {flags}".encode())
            returned.value = flags & ~2
            return CONTINUE if flags & 2 else COMPLETE
        if self._in(token) != b"AP-REP":
            minor.value = 0x96C73A1F  # a krb5 com_err code, as unsigned
            return DEFECTIVE_TOKEN
        returned.value = flags
        return COMPLETE

    def _gss_accept_sec_context(
        self,
        minor: Any,
        handle: Any,
        cred: Any,
        token: Any,
        bindings: Any,
        source: Any,
        mech: Any,
        output: Any,
        returned: Any,
        lifetime: Any,
        delegated: Any,
    ) -> int:
        assert source is None and mech is None and delegated is None
        data = self._in(token)
        if not data.startswith(b"AP-REQ "):
            self._out(output, b"KRB-ERROR")
            return DEFECTIVE_TOKEN
        _, target, flags = data.decode().split(" ")
        handle.value = self._new({"target": target, "flags": int(flags), "initiator": USER})
        returned.value = int(flags)
        self._out(output, b"AP-REP" if int(flags) & 2 else b"")
        return COMPLETE

    def _gss_delete_sec_context(self, minor: Any, handle: Any, output: Any) -> int:
        assert output is None
        del self.objects[handle.value]
        handle.value = None
        return COMPLETE

    def _gss_inquire_context(
        self,
        minor: Any,
        handle: Any,
        source: Any,
        target: Any,
        lifetime: Any,
        mech: Any,
        flags: Any,
        local: Any,
        is_open: Any,
    ) -> int:
        failed = self._failed("gss_inquire_context", minor)
        if failed is not None:
            return failed
        context = self.objects[handle.value]
        source.value = self._new(("name", context["initiator"]))
        target.value = self._new(("name", context["target"]))
        chosen = self.inquire_flags
        flags.value = context["flags"] if chosen is None else chosen
        return COMPLETE

    # -- message protection ------------------------------------------------------------------

    def _gss_wrap(
        self, minor: Any, handle: Any, conf: int, qop: int, data: Any, state: Any, output: Any
    ) -> int:
        failed = self._failed("gss_wrap", minor)
        if failed is not None:
            return failed
        encrypted = bool(conf) and not self.no_conf
        state.value = int(encrypted)
        self._out(output, (b"WC:" if encrypted else b"WI:") + self._in(data))
        return COMPLETE

    def _gss_unwrap(
        self, minor: Any, handle: Any, token: Any, output: Any, state: Any, qop: Any
    ) -> int:
        failed = self._failed("gss_unwrap", minor)
        if failed is not None:
            self._out(output, b"")
            return failed
        data = self._in(token)
        if data[:3] not in (b"WC:", b"WI:"):
            return BAD_MIC
        state.value = int(data[:3] == b"WC:")
        self._out(output, data[3:])
        return COMPLETE

    def _gss_get_mic(self, minor: Any, handle: Any, qop: int, data: Any, output: Any) -> int:
        failed = self._failed("gss_get_mic", minor)
        if failed is not None:
            return failed
        self._out(output, b"MIC:" + self._in(data))
        return COMPLETE

    def _gss_verify_mic(self, minor: Any, handle: Any, data: Any, token: Any, qop: Any) -> int:
        failed = self._failed("gss_verify_mic", minor)
        if failed is not None:
            return failed
        return COMPLETE if self._in(token) == b"MIC:" + self._in(data) else BAD_MIC


# -- python-gssapi ------------------------------------------------------------------------------


def fake_gssapi_module() -> types.SimpleNamespace:
    """Enough of python-gssapi for the ``gssapi`` backend: the same toy mechanism."""

    class GeneralError(Exception):
        pass

    class GSSError(Exception):
        def __init__(self, maj_code: int, min_code: int, message: str = "") -> None:
            super().__init__(message or f"GSS error {maj_code:#x}/{min_code}")
            self.maj_code = maj_code
            self.min_code = min_code
            self.message = message

        def get_all_statuses(self, code: int, is_major: bool) -> list[str]:
            if is_major:
                return [self.message] if self.message else []
            if code == 1:  # python-gssapi's text when it cannot decode a code
                return ["gss_display_status call returned failure (major 327680, minor 22)"]
            return [f"minor text {code}"] if code else []

    module = types.SimpleNamespace()
    module.exceptions = types.SimpleNamespace(GSSError=GSSError, GeneralError=GeneralError)
    module.NameType = types.SimpleNamespace(
        hostbased_service="hostbased", kerberos_principal="principal"
    )
    module.MechType = types.SimpleNamespace(kerberos="krb5")
    module.fail: dict[str, BaseException] = {}  # type: ignore[misc]
    module.flags_override = None

    def maybe_fail(name: str) -> None:
        if name in module.fail:
            raise module.fail.pop(name)

    class Name:
        def __init__(self, text: str, kind: str) -> None:
            maybe_fail("Name")
            if kind == "hostbased":
                service, _, host = text.partition("@")
                text = f"{service}/{host or 'localhost'}@XGFAL.TEST"
            self.text = text

        def __str__(self) -> str:
            return self.text

    class Credentials:
        def __init__(self, **kwargs: Any) -> None:
            maybe_fail("Credentials")
            self.kwargs = kwargs
            module.last_credentials = kwargs

    class Flag(int):
        pass

    class WrapResult(types.SimpleNamespace):
        pass

    class SecurityContext:
        def __init__(self, **kwargs: Any) -> None:
            maybe_fail("SecurityContext")
            self.kwargs = kwargs
            self.usage = kwargs["usage"]
            self._complete = False
            self._last_err: BaseException | None = None
            self.flags = int(kwargs.get("flags") or 0)
            self.initiator_name = Name(USER, "principal")
            self.target_name = kwargs.get("name")

        @property
        def complete(self) -> bool:
            # python-gssapi's acceptor: a failure with an error token is
            # returned from step() and raised here.
            if self._last_err is not None:
                raise self._last_err
            return self._complete

        @property
        def actual_flags(self) -> list[Flag]:
            maybe_fail("actual_flags")
            flags = self.flags if module.flags_override is None else module.flags_override
            return [Flag(1 << bit) for bit in range(8) if flags & (1 << bit)]

        def step(self, token: bytes | None) -> bytes | None:
            maybe_fail("step")
            if self.usage == "initiate":
                if token is None:
                    self._complete = not self.flags & 2
                    return f"AP-REQ {self.target_name} {self.flags}".encode()
                if token != b"AP-REP":
                    raise GSSError(9 << 16, 0, "Invalid token was supplied")
                self._complete = True
                return None
            assert token is not None
            if not token.startswith(b"AP-REQ "):
                self._last_err = GSSError(9 << 16, 0, "Invalid token was supplied")
                return b"KRB-ERROR"
            _, target, flags = token.decode().split(" ")
            self.target_name = Name(target, "principal")
            self.flags = int(flags)
            self._complete = True
            return b"AP-REP" if self.flags & 2 else None

        def wrap(self, data: bytes, encrypt: bool) -> WrapResult:
            maybe_fail("wrap")
            encrypted = encrypt and not getattr(module, "no_conf", False)
            return WrapResult(message=(b"WC:" if encrypted else b"WI:") + data, encrypted=encrypted)

        def unwrap(self, token: bytes) -> WrapResult:
            maybe_fail("unwrap")
            if token[:3] not in (b"WC:", b"WI:"):
                raise GSSError(6 << 16, 0, "A token had an invalid Message Integrity Check (MIC)")
            return WrapResult(message=token[3:], encrypted=token[:3] == b"WC:", qop=0)

        def get_signature(self, data: bytes) -> bytes:
            maybe_fail("get_signature")
            return b"MIC:" + data

        def verify_signature(self, data: bytes, mic: bytes) -> int:
            maybe_fail("verify_signature")
            if mic != b"MIC:" + data:
                raise GSSError(6 << 16, 0, "")
            return 0

    module.Name = Name
    module.Credentials = Credentials
    module.SecurityContext = SecurityContext
    return module
