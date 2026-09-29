"""GSS-API through the optional ``gssapi`` package (python-gssapi).

When the package is installed it is preferred: it is a maintained binding
over the same system library, it knows that library's quirks, and a site
that installed it (``xrdclient[krb5]`` does) has chosen it. The module is
passed in rather than imported here, so this file never needs it to exist.
"""

from __future__ import annotations

import errno
from typing import Any

from ._base import HOSTBASED, Backend, Mechanism, Target
from ._status import KerberosError, describe

__all__ = ["GssapiBackend", "GssapiMechanism"]

#: What python-gssapi says when ``gss_display_status`` could not decode a code.
_UNDECODED = "gss_display_status call returned failure"


class GssapiBackend(Backend):
    """Contexts built with ``gssapi.SecurityContext``."""

    name = "gssapi"

    def __init__(self, module: Any) -> None:
        self.gssapi = module
        self.errors: tuple[type[BaseException], ...] = (
            module.exceptions.GSSError,
            module.exceptions.GeneralError,
            NotImplementedError,
        )

    def fail(self, what: str, exc: BaseException, *, protection: bool = False) -> KerberosError:
        """``exc`` from the package, as a ``KerberosError``."""
        major = int(getattr(exc, "maj_code", 0) or 0)
        minor = int(getattr(exc, "min_code", 0) or 0)
        if isinstance(exc, NotImplementedError):
            # The library lacks an extension (credential stores, most often).
            return KerberosError(f"{what} failed: {exc}", errno.EOPNOTSUPP)
        if not major:
            # ``GeneralError``: the package's own complaint, not the library's.
            return KerberosError(f"{what} failed: {exc}", errno.EACCES)
        # ``GSSError.get_all_statuses`` is ``gss_display_status``; MIT keeps
        # the detailed minor text per thread, so this runs straight after the
        # failure, and a message saying the lookup itself failed is dropped.
        statuses: Any = getattr(exc, "get_all_statuses", lambda code, is_major: [])
        texts = [str(text) for text in statuses(major, True)]
        details = [str(text) for text in statuses(minor, False) if _UNDECODED not in str(text)]
        return describe(what, major, minor, texts, details, protection=protection)

    def _name(self, target: Target) -> Any:
        kinds = self.gssapi.NameType
        kind = kinds.hostbased_service if target.kind == HOSTBASED else kinds.kerberos_principal
        return self.gssapi.Name(target.name, kind)

    def initiator(self, target: Target, flags: int, ccache: str | None) -> Mechanism:
        g = self.gssapi
        try:
            creds = None
            if ccache:
                creds = g.Credentials(
                    usage="initiate", mechs=[g.MechType.kerberos], store={"ccache": ccache}
                )
            context = g.SecurityContext(
                name=self._name(target),
                mech=g.MechType.kerberos,
                flags=flags,
                usage="initiate",
                creds=creds,
            )
        except self.errors as exc:
            raise self.fail("preparing Kerberos authentication", exc) from exc
        return GssapiMechanism(self, context)

    def acceptor(self, name: Target | None, keytab: str | None) -> Mechanism:
        g = self.gssapi
        try:
            creds = None
            if name is not None or keytab:
                creds = g.Credentials(
                    name=self._name(name) if name is not None else None,
                    usage="accept",
                    mechs=[g.MechType.kerberos],
                    store={"keytab": keytab} if keytab else None,
                )
            context = g.SecurityContext(creds=creds, usage="accept")
        except self.errors as exc:
            raise self.fail("preparing a Kerberos acceptor", exc) from exc
        return GssapiMechanism(self, context)


class GssapiMechanism(Mechanism):
    """A ``gssapi.SecurityContext``, with its exceptions translated."""

    def __init__(self, backend: GssapiBackend, context: Any) -> None:
        self.backend = backend
        self.context = context
        self.complete = False

    def step(self, token: bytes) -> bytes:
        out = None
        try:
            out = self.context.step(token or None)
            # An acceptor that fails with an error token to send returns the
            # token from ``step`` and raises the failure from ``complete``.
            complete = bool(self.context.complete)
        except self.backend.errors as exc:
            error = self.backend.fail("Kerberos authentication", exc)
            error.token = bytes(out or b"")
            raise error from exc
        self.complete = complete
        return bytes(out or b"")

    def wrap(self, data: bytes, confidential: bool) -> tuple[bytes, bool]:
        try:
            result = self.context.wrap(data, confidential)
        except self.backend.errors as exc:
            raise self.backend.fail("gss_wrap", exc, protection=True) from exc
        return bytes(result.message), bool(result.encrypted)

    def unwrap(self, token: bytes) -> tuple[bytes, bool]:
        try:
            result = self.context.unwrap(token)
        except self.backend.errors as exc:
            raise self.backend.fail("gss_unwrap", exc, protection=True) from exc
        return bytes(result.message), bool(result.encrypted)

    def get_mic(self, data: bytes) -> bytes:
        try:
            return bytes(self.context.get_signature(data))
        except self.backend.errors as exc:
            raise self.backend.fail("gss_get_mic", exc, protection=True) from exc

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        try:
            self.context.verify_signature(data, mic)
        except self.backend.errors as exc:
            raise self.backend.fail("gss_verify_mic", exc, protection=True) from exc

    def inquire(self) -> tuple[str, str, int]:
        context = self.context
        try:
            flags = 0
            for flag in context.actual_flags:
                flags |= int(flag)
            return str(context.initiator_name), str(context.target_name), flags
        except self.backend.errors as exc:
            raise self.backend.fail("gss_inquire_context", exc) from exc

    def close(self) -> None:
        # The package deletes the context when the object is collected.
        self.context = None
