"""Read-only cache diagnostics delegated to the optional pykrb5 binding."""

from __future__ import annotations

import errno

from ._status import KerberosError


def inspect_cache(name: str | None = None) -> dict[str, str | int]:
    """Describe the selected cache without exporting its keys or contacting a KDC."""
    try:
        import krb5  # type: ignore[import-not-found,unused-ignore]
    except (ImportError, OSError) as exc:
        raise KerberosError(
            "Native Kerberos cache support is not installed. "
            "Install it with python -m pip install 'xgfalclient[krb5]'.",
            errno.EPROTONOSUPPORT,
        ) from exc
    try:
        context = krb5.init_context()
        cache_name = name.encode("utf-8") if name is not None else krb5.cc_default_name(context)
        cache = krb5.cc_resolve(context, cache_name)
        principal = (krb5.cc_get_principal(context, cache).name or b"").decode("utf-8", "replace")
        expires = max((value.times.endtime for value in cache), default=0)
    except krb5.Krb5Error as exc:
        raise KerberosError(
            f"Cannot read Kerberos cache {name or 'default'!r}: {exc}. "
            "Check KRB5CCNAME and your file permissions, then run kinit.",
            errno.EACCES,
            minor=exc.err_code,
        ) from exc
    return {
        "name": cache_name.decode("utf-8", "replace"),
        "principal": principal,
        "expires_at": expires,
    }
