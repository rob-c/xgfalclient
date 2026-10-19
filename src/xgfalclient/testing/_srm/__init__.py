"""The machinery behind :mod:`xgfalclient.testing.srm`, one concern per module.

The facade keeps :class:`~xgfalclient.testing.srm.SRMServer` itself - its
configuration, lifecycle, addressing, test knobs and SOAP dispatch - which
inherits the operations from the mixins here:

* :mod:`.model` - injected replies, spaces, requests and status helpers;
* :mod:`.http` - the httpg request handler and socket server;
* :mod:`.base` - the state and helpers the operation mixins share;
* :mod:`.namespace` - ``srmLs`` and the other namespace operations;
* :mod:`.requests` - asynchronous get/put/bring-online requests;
* :mod:`.space` - space-token operations.

Import from the facade, not from here: these modules are private and their
layout may change.
"""
