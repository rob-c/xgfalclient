"""Cryptography the grid needs and the standard library lacks.

Everything here is a thin, grid-shaped layer over pyca ``cryptography`` (and,
for Kerberos, xrdsec's GSS-API layer over the ``gssapi`` package): since
0.4.0 no cipher, curve or ASN.1 arithmetic is implemented locally. What
remains is the protocol glue the
libraries do not provide:

* :mod:`.x509` and :mod:`.proxy` - gfal2's view of grid certificates, and
  signing gridsite delegation requests.
* :mod:`.sshkeys`, :mod:`.ciphers`, :mod:`.chacha`, :mod:`.x25519`,
  :mod:`.bcrypt` - the SSH transport's keys, ciphers and key exchange.
* :mod:`.krb5` - GSS-API/Kerberos contexts for Csec and dcap: gfal2's
  ``GError`` and backend choice over :mod:`xrdsec.krb5.gss`.
* :mod:`.aes`, :mod:`.der`, :mod:`.ed25519`, :mod:`.p256`, :mod:`.rsa`,
  :mod:`.voms` - compatibility aliases of modules that moved to
  xrdsec (``xrdsec.aes`` and so on), kept so existing imports keep working;
  :mod:`.gsi` likewise, for :mod:`xrdsec.gsi.gss` (Globus GSI: TLS with
  in-band proxy delegation, as GridFTP, LFC's Csec, dcap and SRM speak it).

Importing this package imports nothing: each submodule is loaded on demand,
because ``import gfal2`` must stay cheap for programs that never use a grid
credential.
"""
