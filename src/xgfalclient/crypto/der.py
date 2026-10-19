"""Compatibility import; the shared implementation is :mod:`xrdsec.der`.

Since 0.4.0 the grid's security code lives once, in xrdsec, for xrdclient,
xgfalclient and xrdarc alike. This module replaces itself in ``sys.modules``
with the xrdsec module rather than re-exporting its names: a test that
monkeypatches ``xgfalclient.crypto.der.X`` must patch the very object the
code calls, and ``isinstance`` checks against its classes must agree whichever
name the class was imported under. The re-exported ``__all__`` is for type
checkers and readers; at run time the alias is what callers get. New code imports
:mod:`xrdsec.der` directly.
"""

import sys

from xrdsec import der as _shared
from xrdsec.der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_GENERALIZED_TIME,
    TAG_IA5_STRING,
    TAG_INTEGER,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_PRINTABLE_STRING,
    TAG_SEQUENCE,
    TAG_SET,
    TAG_UTC_TIME,
    TAG_UTF8_STRING,
    DERError,
    Element,
    bit_string,
    boolean,
    decode_time,
    encode,
    encode_integer,
    encode_oid,
    encode_time,
    explicit,
    generalized_time,
    integer,
    null,
    octet_string,
    oid,
    oid_string,
    parse,
    parse_all,
    parse_one,
    printable_string,
    raw_children,
    read_integer,
    sequence,
    set_of,
    tlv,
    utc_time,
    utf8_string,
    validity_time,
)

__all__ = [
    "TAG_BIT_STRING",
    "TAG_BOOLEAN",
    "TAG_GENERALIZED_TIME",
    "TAG_IA5_STRING",
    "TAG_INTEGER",
    "TAG_NULL",
    "TAG_OCTET_STRING",
    "TAG_OID",
    "TAG_PRINTABLE_STRING",
    "TAG_SEQUENCE",
    "TAG_SET",
    "TAG_UTC_TIME",
    "TAG_UTF8_STRING",
    "DERError",
    "Element",
    "bit_string",
    "boolean",
    "decode_time",
    "encode",
    "encode_integer",
    "encode_oid",
    "encode_time",
    "explicit",
    "generalized_time",
    "integer",
    "null",
    "octet_string",
    "oid",
    "oid_string",
    "parse",
    "parse_all",
    "parse_one",
    "printable_string",
    "raw_children",
    "read_integer",
    "sequence",
    "set_of",
    "tlv",
    "utc_time",
    "utf8_string",
    "validity_time",
]

sys.modules[__name__] = _shared
