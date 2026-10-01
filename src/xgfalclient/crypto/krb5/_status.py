"""GSS-API status codes, and what they mean to a gfal2 caller.

A GSS-API call reports a *major* status (the RFC 2744 routine and calling
errors, identical in every implementation) and a *minor* status (the
mechanism's own code: for krb5, a com_err value from the ``krb5`` or
``k5g`` table, or a plain ``errno``). Both backends end up here so that a
missing ticket, an unreachable KDC or a tampered token read the same way and
carry the same ``errno`` whichever library produced them.
"""

from __future__ import annotations

import errno

from ...errors import GError

__all__ = [
    "KerberosError",
    "COMPLETE",
    "CONTINUE_NEEDED",
    "is_error",
    "errno_for",
    "hint_for",
    "routine_text",
    "signed",
    "describe",
]

COMPLETE = 0
CONTINUE_NEEDED = 1

CALLING_MASK = 0xFF000000
ROUTINE_MASK = 0x00FF0000
SUPPLEMENTARY_MASK = 0x0000FFFF

# Routine errors, as the number in bits 16-23 of the major status.
BAD_MECH = 1
BAD_NAME = 2
BAD_NAMETYPE = 3
BAD_BINDINGS = 4
BAD_STATUS = 5
BAD_MIC = 6
NO_CRED = 7
NO_CONTEXT = 8
DEFECTIVE_TOKEN = 9
DEFECTIVE_CREDENTIAL = 10
CREDENTIALS_EXPIRED = 11
CONTEXT_EXPIRED = 12
FAILURE = 13
BAD_QOP = 14
UNAUTHORIZED = 15
UNAVAILABLE = 16
DUPLICATE_ELEMENT = 17
NAME_NOT_MN = 18

#: RFC 2744's words for each routine error, for when the library cannot
#: say it itself (``gss_display_status`` failing, or a fake library).
_ROUTINE_TEXT = {
    BAD_MECH: "An unsupported mechanism was requested",
    BAD_NAME: "An invalid name was supplied",
    BAD_NAMETYPE: "A supplied name was of an unsupported type",
    BAD_BINDINGS: "Incorrect channel bindings were supplied",
    BAD_STATUS: "An invalid status code was supplied",
    BAD_MIC: "A token had an invalid Message Integrity Check (MIC)",
    NO_CRED: "No credentials were supplied, or the credentials were unavailable",
    NO_CONTEXT: "No context has been established",
    DEFECTIVE_TOKEN: "Invalid token was supplied",
    DEFECTIVE_CREDENTIAL: "Invalid credential was supplied",
    CREDENTIALS_EXPIRED: "The referenced credential has expired",
    CONTEXT_EXPIRED: "The referenced context has expired",
    FAILURE: "Unspecified GSS failure",
    BAD_QOP: "The quality-of-protection requested could not be provided",
    UNAUTHORIZED: "The operation is forbidden by local security policy",
    UNAVAILABLE: "The operation or option is not available or unsupported",
    DUPLICATE_ELEMENT: "The requested credential element already exists",
    NAME_NOT_MN: "The provided name was not a mechanism name",
}

#: The ``errno`` for each routine error during context establishment. A
#: failure to authenticate is ``EACCES`` whatever the detail, as gfal2's
#: plugins report it; name and argument problems are the caller's
#: ``EINVAL``; a missing mechanism is ``EPROTONOSUPPORT``.
_ROUTINE_ERRNO = {
    BAD_MECH: errno.EPROTONOSUPPORT,
    BAD_NAME: errno.EINVAL,
    BAD_NAMETYPE: errno.EINVAL,
    BAD_STATUS: errno.EINVAL,
    NO_CONTEXT: errno.EPROTO,
    DEFECTIVE_TOKEN: errno.EPROTO,
    BAD_QOP: errno.EINVAL,
    UNAVAILABLE: errno.EOPNOTSUPP,
    DUPLICATE_ELEMENT: errno.EEXIST,
    NAME_NOT_MN: errno.EINVAL,
}

# Minor statuses worth recognising: com_err codes from MIT's ``krb5`` table
# (Heimdal uses the same numbers) and MIT's ``k5g`` GSS table.
_KRB5_BASE = -1765328384
KDC_ERR_S_PRINCIPAL_UNKNOWN = _KRB5_BASE + 7
AP_ERR_TKT_EXPIRED = _KRB5_BASE + 32
AP_ERR_SKEW = _KRB5_BASE + 37
CC_NOTFOUND = _KRB5_BASE + 141
KDC_UNREACH = _KRB5_BASE + 156
FCC_NOFILE = _KRB5_BASE + 195
KG_TGT_MISSING = 39756034
KG_EMPTY_CCACHE = 39756044

_NO_TICKET = frozenset(
    {AP_ERR_TKT_EXPIRED, CC_NOTFOUND, FCC_NOFILE, KG_TGT_MISSING, KG_EMPTY_CCACHE}
)
_NO_TICKET_ROUTINES = frozenset({NO_CRED, DEFECTIVE_CREDENTIAL, CREDENTIALS_EXPIRED})


class KerberosError(GError):
    """A GSS-API failure: a ``GError`` that also keeps the raw statuses.

    ``token`` is whatever the library produced alongside the failure - an
    acceptor's ``KRB-ERROR`` reply, which the protocol may forward so the
    initiator learns why it was refused.
    """

    def __init__(
        self, message: str, code: int, major: int = 0, minor: int = 0, token: bytes = b""
    ) -> None:
        super().__init__(message, code)
        self.major = major
        self.minor = minor
        self.token = token

    def __reduce__(self) -> tuple[type[GError], tuple[str, int]]:
        return (KerberosError, (self.message, self.code))


def signed(minor: int) -> int:
    """A minor status as the signed 32-bit com_err value it was built as."""
    minor &= 0xFFFFFFFF
    return minor - (1 << 32) if minor & 0x80000000 else minor


def is_error(major: int) -> bool:
    """``GSS_ERROR()``: a calling or routine error (supplementary bits aside)."""
    return bool(major & (CALLING_MASK | ROUTINE_MASK))


def routine_text(major: int) -> str:
    """RFC 2744's description of ``major``'s routine error."""
    if major & CALLING_MASK:
        return "A required argument was invalid or missing"
    routine = (major & ROUTINE_MASK) >> 16
    if routine:
        return _ROUTINE_TEXT.get(routine, f"GSS major status 0x{major:08x}")
    return "The token was a duplicate, out of sequence or too old"


def errno_for(major: int, minor: int, *, protection: bool = False) -> int:
    """The ``errno`` a failed call stands for.

    ``protection`` marks message protection (wrap, unwrap, MIC), where a bad
    signature or a replayed token is a corrupt stream (``EPROTO``) rather
    than an authentication refusal.
    """
    code = signed(minor)
    if code in (KDC_UNREACH, errno.ETIMEDOUT):
        return errno.ETIMEDOUT
    if code == errno.ECONNREFUSED:
        return errno.ECONNREFUSED
    if major & CALLING_MASK:
        return errno.EINVAL
    routine = (major & ROUTINE_MASK) >> 16
    if routine == 0 or (protection and routine == BAD_MIC):
        # Only supplementary bits (a replayed or reordered token), or a
        # message whose signature does not verify: the stream is corrupt.
        return errno.EPROTO
    return _ROUTINE_ERRNO.get(routine, errno.EACCES)


def hint_for(major: int, minor: int) -> str:
    """What the user can do about it, when there is something obvious."""
    code = signed(minor)
    routine = (major & ROUTINE_MASK) >> 16
    if code in _NO_TICKET or routine in _NO_TICKET_ROUTINES:
        return " (no valid Kerberos ticket: run kinit, or point KRB5CCNAME at a credential cache)"
    if code == KDC_ERR_S_PRINCIPAL_UNKNOWN:
        return " (the KDC does not know the service principal: check the host name)"
    if code == AP_ERR_SKEW:
        return " (the clocks of this host and the server differ too much)"
    if code == KDC_UNREACH:
        return " (no KDC answered: check the network and krb5.conf)"
    return ""


def describe(
    what: str,
    major: int,
    minor: int,
    major_texts: list[str],
    minor_texts: list[str],
    *,
    protection: bool = False,
    token: bytes = b"",
) -> KerberosError:
    """The ``KerberosError`` for a failed call, from the library's own words.

    Both backends word failures the same way: what was being done, then the
    library's messages. MIT's ``GSS_S_FAILURE`` text ("Unspecified GSS
    failure. Minor code may provide more information") is dropped when the
    minor code does provide it, and a supplementary-only status (a replayed
    token) leaves out the minor text, which MIT gives as "Success".
    """
    routine = (major & ROUTINE_MASK) >> 16
    parts = list(major_texts) or [routine_text(major)]
    if minor and is_error(major):
        detail = list(minor_texts) or [f"minor code {signed(minor)}"]
        parts = detail if routine == FAILURE and minor_texts else parts + detail
    message = f"{what} failed: {': '.join(parts)}{hint_for(major, minor)}"
    return KerberosError(
        message, errno_for(major, minor, protection=protection), major, minor, token
    )
