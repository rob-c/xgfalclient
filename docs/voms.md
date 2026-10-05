# VOMS proxies

A VOMS proxy is an RFC 3820 X.509 proxy containing signed attribute
certificates. xgfalclient sends the original chain on every X.509 path —
WebDAV and SRM mutual TLS, GridFTP and dCache GSI, and XRootD through
xrdclient — so an existing VOMS proxy uses the usual X.509 authentication flow.

## Inspect and validate

The portable verifier exposes the VO, ordered FQANs and VOMS generic
attributes and gives every AC a typed verdict:

```python
import os

from xgfalclient.crypto.voms import inspect_voms, validate_voms
from xgfalclient.crypto.x509 import load_credential

credential = load_credential(os.environ["X509_USER_PROXY"])

# Decode claims for diagnostics. Do not authorize from this result.
claims = inspect_voms(credential.chain)
print(claims.entries)

# Authenticate every claim against the local grid trust installation.
trusted = validate_voms(credential.chain)
if not trusted.verified:
    raise RuntimeError(trusted.message)

print(trusted.vos)
print(trusted.fqans)
```

Validation checks the AC version, holder binding through delegated proxy
parents, validity, embedded signer and signature, issuer, optional target
host, signer CA path, unknown critical extensions and the VO's `.lsc` file.
VOMS server signatures using RSA PKCS#1 with SHA-1 through SHA-512, RSA-PSS,
ECDSA P-256 with SHA-256, or Ed25519 are accepted; MD5-class, unsupported
curves and unknown algorithms fail closed.
Successfully decoded ACs are checked independently, so an expired or untrusted
VO does not poison another verified entry.

The current CA-chain check covers signatures, issuer names and validity dates,
not full RFC 5280 extension constraints or certificate revocation lists (CRLs).
Do not use it as a complete replacement for an established path validator.

## Trust paths on macOS

CA certificates and VOMS server bindings are resolved in this order:

1. `$X509_CERT_DIR` and `$X509_VOMS_DIR`;
2. `/etc/grid-security/certificates` and `/etc/grid-security/vomsdir`;
3. `/opt/homebrew/etc/grid-security/...` on Apple Silicon Homebrew;
4. `/usr/local/etc/grid-security/...` on Intel Homebrew.

Set the two environment variables when the trust bundle lives elsewhere.
Missing trust material is a failed `untrusted` or `lsc` verdict, never a
silent downgrade.

## Clear diagnostics

`result.message` explains the failure and suggests a fix. `result.diagnostics`
contains stable `code`, `message`, `path` and `errno` fields. These distinguish
missing, unreadable, empty and damaged CA files, expired CA versus signer
certificates, and missing, malformed or mismatched `.lsc` files. Expiry
messages include UTC dates; filesystem failures retain the actual path.
Rejected entries remain visible even when another VO verifies successfully.

Use the VO administrator's official trust files. Do not fix a mismatch by
copying the signer out of an untrusted proxy or making private keys readable
by everyone. Trust files need to be readable and their directories accessible
to the account running the client.

Endpoint configuration is separate from trust:

```python
from xgfalclient.crypto.voms import check_vomses

# Either a vomses file or a directory containing vomses files.
for issue in check_vomses("/etc/vomses"):
    print(issue.message)
```

This preflight checks UTF-8, the five endpoint fields, port ranges and file
access, without contacting servers or changing files. It is intended for
debugging proxy acquisition. Missing `vomses` does not prevent using an
already-issued proxy; it is never required by `validate_voms`. A successful
preflight does not prove an endpoint reachable or trusted.

The VO's VOMS service signs its assertions. This client validates and transports
an existing proxy; it does not request or mint new assertions.
