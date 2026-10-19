"""The pieces of :mod:`xgfalclient.testing.lfc`: model, connection, namespace, handlers.

:mod:`xgfalclient.testing.lfc` is the public facade: it defines
:class:`~xgfalclient.testing.lfc.LFCServer` (the listener, the catalogue
and its test helpers, fault injection) and re-exports everything below, so
tests import from there. The server mirrors ``lfcdaemon``'s own layering:

* :mod:`.model` - the catalogue rows (:class:`Entry`, :class:`ReplicaEntry`),
  who a connection is (:class:`Identity`), the injections a test queues
  (:class:`Raw`, :class:`Hangup`) and the server's constants;
* :mod:`.connection` - :class:`_Connection`, one client's socket
  (``Cns_main.c``'s ``doit``): Csec negotiation (``GSI``/``ID``), the id
  mapping, reading requests, sessions and directory listings;
* :mod:`.namespace` - ``Cns_parsepath``, ``Cns_chkentryperm`` and the other
  catalogue rules every request type shares, plus the record marshalling;
* :mod:`.handlers` - one ``_h_<request>`` function per Cns request type
  (``Cns_procreq.c``), and the :data:`_HANDLERS` table dispatch looks them up in.

The facade re-exports the same objects, not copies: a test that does
``monkeypatch.setitem(lfc._HANDLERS, ...)`` changes the table
:meth:`_Connection.process` reads, and one patching ``lfc.TokenLink.send_token``
patches the class the connection instantiates. No name is looked up through
the facade at call time.
"""
