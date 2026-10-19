"""What ``import gfal2`` holds, for type checkers.

At run time ``src/gfal2/__init__.py`` replaces itself with the module
``xgfalclient._gfal2_module()`` fills: python3-gfal2's names, which are
xgfalclient's public API less ``install_as_gfal2`` and ``VERSION``, with the
bindings' ``__version__``. tests/test_gfal2_shim.py holds this list to it.
"""

from xgfalclient import Credential as Credential
from xgfalclient import DirectoryType as DirectoryType
from xgfalclient import Dirent as Dirent
from xgfalclient import FileType as FileType
from xgfalclient import GError as GError
from xgfalclient import Gfal2Context as Gfal2Context
from xgfalclient import GfaltEvent as GfaltEvent
from xgfalclient import NullHandler as NullHandler
from xgfalclient import Stat as Stat
from xgfalclient import TransferParameters as TransferParameters
from xgfalclient import checksum_mode as checksum_mode
from xgfalclient import creat_context as creat_context
from xgfalclient import cred_clean as cred_clean
from xgfalclient import cred_new as cred_new
from xgfalclient import cred_set as cred_set
from xgfalclient import event_side as event_side
from xgfalclient import get_version as get_version
from xgfalclient import set_verbose as set_verbose
from xgfalclient import verbose_level as verbose_level

#: python3-gfal2's version (``1.13.1``), not xgfalclient's.
__version__: str
