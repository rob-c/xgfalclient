"""The machinery behind :mod:`xgfalclient.testing.gridftp`, one concern per module.

The facade keeps :class:`~xgfalclient.testing.gridftp.GridFTPServer` (the
listener, its configuration and fault tables) and ``DATA_TIMEOUT``; what one
control connection does is here:

* :mod:`.common` - the reply/hang-up exceptions, the perf-marker counter,
  ``CKSM`` and the globus error codes;
* :mod:`.base` - per-session state, the (GSI-protected) control channel,
  command dispatch and path confinement;
* :mod:`.commands` - login (``AUTH``/``ADAT``/``USER``/``PASS``) and the
  session-setting verbs;
* :mod:`.data` - passive and active data channels, ``DCAU``/``PROT``, and
  ``MODE S``/``MODE E`` transfers with their markers;
* :mod:`.namespace` - listings and the metadata and namespace verbs;
* :mod:`.session` - :class:`~.session._Session`, the mixins combined.

Import from the facade, not from here: these modules are private and their
layout may change.
"""
