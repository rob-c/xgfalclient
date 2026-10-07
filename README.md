# xgfalclient

gfal2, in Python 3. A drop-in replacement for the `gfal2` Python bindings
(`python3-gfal2`) and the `gfal-*` commands (gfal2-util). General-purpose libraries handle
security-sensitive primitives and parsing.

```python
import xgfalclient as gfal2

with gfal2.creat_context() as ctx:
    print(ctx.stat("davs://se.example.org/store/f.root").st_size)

    params = ctx.transfer_parameters()
    params.overwrite = True
    params.set_checksum(gfal2.checksum_mode.both, "ADLER32", "")
    ctx.filecopy(params, "file:///tmp/f.root", "root://se.example.org//store/f.root")
```

Unmodified code that says `import gfal2` works as it is: the wheel also
installs a `gfal2` module (reporting the bindings' version, 1.13.1, while
`get_version()` reports gfal2 2.23.5) and gfal2-util's `gfal2_util` package;
`xgfalclient.install_as_gfal2()` does the same for one process explicitly.
Because of that, don't install it into a Python environment that also has the
`python3-gfal2` RPM on its path - whichever comes first on `sys.path` wins.
Install it in a virtual environment. On EL9 a `pip install --user` (in
`~/.local`) or a root `pip install` (in `/usr/local`) comes before the RPMs
on `sys.path`, so it takes over every `import gfal2` and also the RPM's own
`/usr/bin/gfal-*`, which run the first `python` that can import `gfal2`.
EL9's pip also has a bug here: a root `pip uninstall xgfalclient` deletes
gfal2-util's `/usr/bin/gfal-*` scripts along with its own.

## Why

The goal is to make scientific data access straightforward for physicists,
administrators and new projects: familiar APIs, one installation workflow,
clear diagnostics and portable Python 3.10+ support. Existing FTS, Rucio and
DIRAC integrations can keep using the interfaces they already know.

## Install

Requires Python 3.10+. Runtime dependencies are `botocore`, `PyJWT[crypto]`,
`urllib3`, `asn1crypto`, `cryptography` and the exact-pinned `xrdclient==0.3.2`.
(Python 3.9 cannot install botocore together with `urllib3>=2.2`, which is
why the floor is 3.10; see [platform status](docs/platforms.md).)
XRootD support is included in the base install. The two clients share one
implementation of VOMS validation, DER/RSA/AES/signature helpers and safe XML
loading; existing `xgfalclient.crypto` import paths remain compatible.
XML parsing uses a local declaration-rejecting wrapper around Python's built-in
parsers; no libxml2, lxml or XML build tools are required. Binary protocol
records use local, bounds-checked readers and standard-library `struct`.
Cryptography supplies native wheels for supported mainstream platforms.

Native Kerberos is optional: `pip install 'xgfalclient[krb5]'` adds python-gssapi
and pykrb5 (distribution name `krb5`). Both have macOS wheels; Linux source
installs need a C compiler and Kerberos development headers. Ordinary installs
and non-Kerberos protocols do not request either binding.

CI checks wheel-only dependency resolution for Python 3.10 and 3.14 on
macOS Intel/Apple Silicon, glibc Linux (2.28+) and musl Linux (1.2+), on x86-64
and ARM64. Clean installs are exercised on Linux and macOS. These gates check
current releases; they cannot guarantee future upstream wheel availability.

Python's built-in XML parser must be kept up to date through Python or
operating-system updates. Parser regression tests cover declaration rejection,
encoded input, malformed records and existing protocol error codes.

The maintained libraries own AWS signing, JWT claim decoding, DER primitives,
cipher/curve operations and connection setup/TLS. Protocol-specific GSI,
RFC 3820/VOMS policy, redirects and upload handshakes remain thin client adapters.


```console
$ pip install xgfalclient              # all protocols, including root://
$ pip install 'xgfalclient[xrootd]'    # compatibility alias; same base install
```

## Protocols

As in gfal2, each protocol is a plugin, loaded the first time a URL needs it.

| Scheme | Plugin | Notes |
| --- | --- | --- |
| `http`, `https`, `dav`, `davs` | http | WebDAV, HTTP third-party copy (pull, push, streamed fallback), Link-discovered Metalink replica failover, gridsite delegation, WLCG tape REST API, SE-issued tokens, CDMI QoS |
| `s3`, `s3s` | http | AWS SigV4, multipart upload, pre-signed TPC |
| `gcloud`, `gclouds` | http | service-account V4 signed URLs, as davix does |
| `swift`, `swifts` | http | OpenStack Swift with a configured token (`[SWIFT]`), as davix does |
| `cs3`, `cs3s` | http | CS3 over HTTP with a bearer token |
| `root`, `roots`, `xroot`, `xroots` | xrootd | through the sibling xrdclient; GSI, tokens, TPC, staging |
| `gsiftp`, `ftp` | gridftp | GSI control channel, MODE E parallel streams, DCAU, third-party copy |
| `srm` | srm | SRM v2.2 over httpg, TURL resolution to the other plugins, BDII endpoint discovery |
| `dcap`, `gsidcap`, `kdcap` | dcap | dCache's native protocol |
| `sftp` | sftp | over the system `ssh`, or a pure-Python SSH-2 transport |
| `lfc` | lfc | the LCG File Catalog (retired from gfal2, kept here) |
| `file` | file | the local filesystem, with gfal2's quirks |
| `mock` | mock | gfal2's test plugin: a storage element described by its URL |

`rfio://` is not supported; neither is it by gfal2 on EL9, which no longer
builds its RFIO plugin.

## Authentication

Everything gfal2 finds, found in the same order: `ctx.cred_set()` per URL
prefix, the `[X509]` and `[BEARER]` options, `X509_USER_PROXY`,
`/tmp/x509up_u<uid>`, `X509_USER_CERT`/`X509_USER_KEY`, `~/.globus`, and
WLCG bearer-token discovery (`BEARER_TOKEN`, `BEARER_TOKEN_FILE`,
`$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>`). Trust anchors come from
`X509_CERT_DIR`, `/etc/grid-security/certificates`, or the standard Homebrew
grid-security prefixes on macOS.

VOMS attribute certificates are carried unchanged on every X.509 protocol
and can be decoded and verified with
`xgfalclient.crypto.voms.validate_voms()`. The verifier checks holder and
validity, the embedded signer and signature, issuer and targets, the CA chain
and `vomsdir` LSC binding; see the
[VOMS guide](docs/voms.md).

GSI framing and RFC 3820 proxy policy remain in Python, with ASN.1 primitives
handled by `asn1crypto` and ciphers/curves by `cryptography`. Legacy raw-RSA
GSI operations and 512-bit compatibility key generation remain local code;
they have not yet been rebased. TLS itself is the standard `ssl` module.

Kerberos (for `kdcap://` and friends) uses the system GSS-API through
the optional `krb5` extra's `gssapi` package (python-gssapi). The old `ctypes` backend
selection is a compatibility alias; no local GSS-API ABI binding remains.
`xgfalclient.crypto.krb5.inspect_cache()` uses pykrb5 for read-only cache
diagnostics, returning the cache name, principal and latest ticket expiry,
never session keys.

`s3://` is signed with the `[S3]` (or per-host `[S3:<HOST>]`) keys, as davix
does, and `gcloud://` with the service-account JSON from `[GCLOUD]
JSON_AUTH_FILE` or `JSON_AUTH_STRING`.
`sftp://` uses the user's own SSH setup - keys, agent and `~/.ssh/config`
through the system `ssh`, or public keys and a password from the credential
store through the built-in SSH-2 client.

## Configuration

The stock gfal2 defaults are built in, and `$GFAL_CONFIG_DIR` (or an existing
`/etc/gfal2.d`) is layered on top, so a site's gfal2 tuning applies unchanged.
`get_opt_*`/`set_opt_*` behave as GLib key files do, error codes included.
Setting `[HTTP PLUGIN] METALINK=true` enables Davix-compatible recovery for
failed HTTP stats, reads, positioned reads and downloads. Discovery uses the
server's Metalink `Link` or content type, caches the catalogue, and only pays
that network cost after the original endpoint fails.

HTTP `GET`, `HEAD`, `OPTIONS` and `PROPFIND` operations retry connection
failures up to `[CORE] CONN_RETRY` times; streamed and positioned reads resume
from the last byte received, and uploads restart only where replay is safe.
When `CONN_RETRY_INTERVAL` is absent, retries use a 50 ms exponential backoff
capped at one second so a brief outage cannot consume the entire retry count
immediately. Setting the interval explicitly to `0` keeps fail-fast retry
timing. Timeouts and server refusals are not mistaken for broken links.

Completed copies to regular `file://` destinations issue one final durability
barrier before reporting success. Delayed `ENOSPC`/`EIO` from a FUSE cache,
network filesystem or failing disk therefore reaches the caller. The barrier
is outside the transfer loop, so it does not reduce streaming throughput. The
stable size must also match the transferred byte count, catching a cache that
acknowledges `fsync` without publishing its writeback journal.

Read-only local opens and reads recover from transient `EAGAIN`, `EBUSY`,
`EINTR`, `ESTALE`, and `ETIMEDOUT` using `[CORE] CONN_RETRY` and
`CONN_RETRY_INTERVAL`. Only a reader that actually faults downshifts to 4 KiB,
and it reopens only if device, inode, size, and nanosecond timestamps still
identify the same file generation. A replaced source therefore fails with
`ESTALE` instead of producing a mixed-generation copy.

## Command line

Every command supports `--json`, `--xml` and `--output-format json|xml`,
including errors, help/version, staging, progress and binary stdout.
See [the machine-output guide](docs/output.md). Text remains the default.

`gfal-copy`, `gfal-ls`, `gfal-stat`, `gfal-mkdir`, `gfal-rm`, `gfal-rename`,
`gfal-sum`, `gfal-cat`, `gfal-save`, `gfal-chmod`, `gfal-xattr`,
`gfal-bringonline`, `gfal-archivepoll`, `gfal-evict` and `gfal-token`, with
gfal2-util 1.9.1's options, output and exit codes; the deprecated
`gfal-legacy-register`, `gfal-legacy-unregister`, `gfal-legacy-replicas` (LFC
replicas) and `gfal-legacy-bringonline`; `gfal2_version` and
`gfal_srm_ifce_version`; man pages for all of them; and
`python -m xgfalclient.cli <command>`.

gfal2-util's Python package is there too, for wrappers that run or extend the
commands in-process: `from gfal2_util.shell import Gfal2Shell`, or a
`gfal2_util.base.CommandBase` subclass with `@base.arg`-decorated
`execute_<name>` methods.

## Where it differs from gfal2

Deliberately, and only where gfal2's behaviour is a bug:

* a copy onto itself with `overwrite` set is refused (`EINVAL`); gfal2
  deletes the source;
* a failed copy cleans up its destination whenever `transfer_cleanup` is set,
  including after a destination checksum mismatch;
* a third-party copy is checked even when no checksum was asked for: the two
  servers' checksums are compared afterwards (`[CORE] VERIFY_THIRD_PARTY`,
  on by default), because a destination can report a pull finished that
  never happened - RAL's Echo did, leaving a full-size file of no data -
  and gfal2 then reports success;
* `TransferParameters.timeout = 0` means no limit; gfal2's local copy
  expires at once;
* error codes are the intended ones where gfal2 reports a stale `errno` or
  a raw protocol status (details in each plugin's module docstring);
* `sftp://` checks host keys (accept-new by default; gfal2 checks none) and
  never passes a password to an `ssh` subprocess.
* a `$X509_USER_PROXY` naming a file that is not there is passed over, so
  token-only access still works, and nothing else is presented in its place:
  not `/tmp/x509up_u<uid>`, which in a pilot job is the pilot's identity
  rather than the payload's. gfal2 presents the missing file and fails.

## Performance

Head to head against gfal2 2.23.5's own Python bindings, same machine, same
servers, 512 MiB transfers (medians; details and method in
[docs/performance.md](docs/performance.md)):

| | download | upload | stat | listdir |
| --- | --- | --- | --- | --- |
| `davs://` | **1.39×** | **1.29×** | **5.6×** | **2.4×** |
| `root://` | **5.1×** | **1.39×** | **1.39×** | **1.32×** |
| `gsiftp://` | **1.46×** | **1.21×** | **2.0×** | **1.84×** |
| `gsidcap://` | **1.54×** | **1.34×** | **14×** | |
| `sftp://` | **1.19-1.37×** | gfal2 truncates | | |

Where it is not ahead: the first `root://` operation in a process pays
about 90 ms to import xrdclient (gfal2 pays its plugin loading inside
`creat_context`). gfal2's sftp upload has no number because it silently
truncates the file; ours writes every byte.

## Development

```console
$ python -m venv .venv && .venv/bin/pip install -e ../xrdclient -e '.[dev]'
$ .venv/bin/pytest -n auto --cov          # 100% line and branch coverage, enforced
$ XGFAL_CONDCOV=1 .venv/bin/pytest -n auto # every and/or, ternary and filter both ways
$ .venv/bin/ruff check src tests && .venv/bin/mypy
```

Tests are hermetic: every protocol has an in-process server in
`xgfalclient.testing`, and a throwaway grid PKI (`xgfalclient.testing.pki`)
mints CAs, host certificates and proxies at run time. Tests against real
servers in Docker are marked `interop` and run with `XGFAL_INTEROP=1`. See
[the documentation](docs/index.md), [developer guide](docs/DEVELOPING.md),
[security policy](SECURITY.md), [contribution guide](CONTRIBUTING.md) and
[0.3.0 release notes](CHANGELOG.md).

## Licence

LGPL-3.0-or-later.
