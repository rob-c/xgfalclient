"""In-process servers and credentials for testing code that uses xgfalclient.

Each protocol plugin is tested over the real wire, against loopback, by a
server in this package - no Docker, no grid services, no ambient
credentials. Import the module you need; this package imports nothing
itself, so ``import xgfalclient`` never pays for the servers.

* :mod:`.pki` - a throwaway grid PKI (CA directory, host and user
  certificates, RFC 3820 and legacy proxies) and the TLS contexts built
  from it; most servers below take ``pki.server_context()``.
* :mod:`.gridftp` - ``ftp://``/``gsiftp://`` (:class:`~.gridftp.GridFTPServer`).
* :mod:`.srm` - SRM v2.2 over httpg (:class:`~.srm.SRMServer`).
* :mod:`.ldap` - a BDII for SRM endpoint discovery (:class:`~.ldap.BDIIServer`).
* :mod:`.webdav`, :mod:`.lfc`, :mod:`.sftp`, :mod:`.dcap` - the other
  protocols' servers.

The servers share a shape: the constructor binds an ephemeral port (read
``port`` or ``url(...)`` right away), ``start()`` serves on daemon threads,
``stop()`` - or leaving the ``with`` block - breaks every connection, and
public attributes (``faults``, ``log``, ...) are the knobs a test turns and
the record it checks. They reproduce the real servers' replies where a
client can tell the difference, and each module docstring says where it
deliberately does less. They are code under test too: the coverage gate
includes them, so a server branch no test reaches should be removed.
"""
