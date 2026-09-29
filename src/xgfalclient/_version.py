"""Versions, in one place.

``__version__`` is this package's own. The gfal2 API it reproduces is
reported as the versions of the toolkit it replaces, because callers gate
on them: ``get_version()`` and the plugin names give gfal2's, and the
``gfal2`` module's ``__version__`` is the Python bindings'.
"""

__version__ = "0.1.0"

#: The gfal2 C library release whose behaviour is reproduced.
GFAL2_VERSION = "2.23.5"

#: The python3-gfal2 bindings release whose API is reproduced.
GFAL2_PYTHON_VERSION = "1.13.1"
