"""The session class the test GridFTP server runs: every verb mixin, combined.

:class:`_Session` adds nothing of its own. Its method resolution order is
``_Commands`` (login and settings), then ``_Namespace`` and ``_DataChannel``
(listings and transfers), then ``_SessionBase`` (state and the control
channel), and :meth:`~.base._SessionBase.handle` finds a verb's handler on
it by name (``do_<VERB>``), wherever in that chain it is defined.
"""

from __future__ import annotations

from .commands import _Commands
from .namespace import _Namespace


class _Session(_Commands, _Namespace):
    """One control connection and its state."""
