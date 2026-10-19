"""The machinery behind :mod:`xgfalclient.testing.sftp`, one layer per module.

* :mod:`.session` - one SFTP v3 session: framing, faults, the request
  handlers and their dispatch table;
* :mod:`.server` - :class:`~.server.SFTPServer` (shared state, faults,
  starting sessions) and the socket helpers;
* :mod:`.transport` - the SSH-2 transport: framing, key exchange, strict
  KEX, user authentication;
* :mod:`.ssh` - :class:`~.ssh.SSHServer` and the session channel that
  carries the ``sftp`` subsystem;
* :mod:`.fake_ssh` - the fake ``ssh`` executable.

Import from the facade, not from here: these modules are private and their
layout may change.
"""
