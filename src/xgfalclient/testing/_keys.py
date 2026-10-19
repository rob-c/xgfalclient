"""The eight frozen test keys, under the name they had before 0.4.0.

The keys live in :mod:`xrdsec.testing._keys` (re-exported as
:data:`xrdsec.testing.pki.KEYS`) so that xrdsec, xrdclient, xgfalclient and
xrdarc mint their test PKIs from one table; that module explains why the
keys are frozen (and public, and protect nothing) and which slot is for
what. This alias keeps ``KEY_0`` ... ``KEY_7`` and :data:`KEYS` importable
from here, slot for slot the same PEM text.
"""

from xrdsec.testing.pki import KEYS as KEYS

KEY_0, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7 = KEYS

__all__ = ["KEYS", "KEY_0", "KEY_1", "KEY_2", "KEY_3", "KEY_4", "KEY_5", "KEY_6", "KEY_7"]
