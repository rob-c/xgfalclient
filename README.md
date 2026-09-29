# xgfalclient

gfal2, in pure Python. A drop-in replacement for the `gfal2` Python bindings
(`python3-gfal2`) and the `gfal-*` commands (gfal2-util), with no C library
underneath and no required dependency outside the standard library.

```python
import xgfalclient as gfal2

ctx = gfal2.creat_context()
print(ctx.stat("davs://se.example.org/store/f.root").st_size)

params = ctx.transfer_parameters()
params.overwrite = True
params.set_checksum(gfal2.checksum_mode.both, "ADLER32", "")
ctx.filecopy(params, "file:///tmp/f.root", "root://se.example.org//store/f.root")
```

Code that must keep saying `import gfal2` can call
`xgfalclient.install_as_gfal2()` once at start-up.

## Why

gfal2 is the data-management layer FTS, Rucio and DIRAC drive, but using it
from Python means a stack of compiled libraries - gfal2, davix, libXrdCl,
Globus, srm-ifce, gSOAP, CGSI - that must match the interpreter, the
distribution and each other. xgfalclient is the same API and the same
behaviour as one `pip install`, on any Python from 3.9 (what RHEL 9 and
AlmaLinux 9 ship) upwards.

## Install

```console
$ pip install xgfalclient              # everything but root://
$ pip install 'xgfalclient[xrootd]'    # root://, via xrdclient (itself pure Python)
```

## Protocols

As in gfal2, each protocol is a plugin, loaded the first time a URL needs it.

| Scheme | Plugin | Notes |
| --- | --- | --- |
| `http`, `https`, `dav`, `davs` | http | WebDAV, HTTP third-party copy (pull, push, streamed fallback), gridsite delegation, WLCG tape REST API, SE-issued tokens, CDMI QoS |
| `s3`, `s3s` | http | AWS SigV4, multipart upload, pre-signed TPC |
| `gcloud`, `gclouds` | http | service-account V4 signed URLs, as davix does |
| `root`, `roots`, `xroot`, `xroots` | xrootd | through xrdclient (pure Python); GSI, tokens, TPC, staging |
| `gsiftp`, `ftp` | gridftp | GSI control channel, MODE E parallel streams, DCAU, third-party copy |
| `srm` | srm | SRM v2.2 over httpg, TURL resolution to the other plugins |
| `dcap`, `gsidcap`, `kdcap` | dcap | dCache's native protocol |
| `sftp` | sftp | over the system `ssh`, or a pure-Python SSH-2 transport |
| `lfc` | lfc | the LCG File Catalog (retired from gfal2, kept here) |
| `file` | file | the local filesystem, with gfal2's quirks |
| `mock` | mock | gfal2's test plugin: a storage element described by its URL |

## Authentication

Everything gfal2 finds, found in the same order: `ctx.cred_set()` per URL
prefix, the `[X509]` and `[BEARER]` options, `X509_USER_PROXY`,
`/tmp/x509up_u<uid>`, `X509_USER_CERT`/`X509_USER_KEY`, `~/.globus`, and
WLCG bearer-token discovery (`BEARER_TOKEN`, `BEARER_TOKEN_FILE`,
`$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>`). Trust anchors come from
`X509_CERT_DIR` or `/etc/grid-security/certificates`.

GSI is implemented in Python: the TLS handshake carried in GSSAPI tokens,
the delegation byte, and proxy delegation - signing an RFC 3820 proxy for a
server's certificate request - with DER, RSA and X.509 written from scratch.
TLS itself is the standard `ssl` module.

Kerberos (for `kdcap://` and friends) goes through the system
`libgssapi_krb5` via `ctypes`, or the `gssapi` package when installed.

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

## Command line

`gfal-copy`, `gfal-ls`, `gfal-stat`, `gfal-mkdir`, `gfal-rm`, `gfal-rename`,
`gfal-sum`, `gfal-cat`, `gfal-save`, `gfal-chmod`, `gfal-xattr`,
`gfal-bringonline`, `gfal-archivepoll`, `gfal-evict` and `gfal-token`, with
gfal2-util 1.9.1's options, output and exit codes; also
`python -m xgfalclient.cli <command>`.

## Where it differs from gfal2

Deliberately, and only where gfal2's behaviour is a bug:

* a copy onto itself with `overwrite` set is refused (`EINVAL`); gfal2
  deletes the source;
* a failed copy cleans up its destination whenever `transfer_cleanup` is set,
  including after a destination checksum mismatch;
* error codes are the intended ones where gfal2 reports a stale `errno` or
  a raw protocol status (details in each plugin's module docstring);
* `sftp://` checks host keys (accept-new by default; gfal2 checks none) and
  never passes a password to an `ssh` subprocess.

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
$ python -m venv .venv && .venv/bin/pip install -e '.[dev,xrootd]'
$ .venv/bin/pytest -n auto --cov          # 100% line and branch coverage, enforced
$ XGFAL_CONDCOV=1 .venv/bin/pytest -n auto # every and/or, ternary and filter both ways
$ .venv/bin/ruff check src tests && .venv/bin/mypy
```

Tests are hermetic: every protocol has an in-process server in
`xgfalclient.testing`, and a throwaway grid PKI (`xgfalclient.testing.pki`)
mints CAs, host certificates and proxies at run time. Tests against real
servers in Docker are marked `interop` and run with `XGFAL_INTEROP=1`. See
[docs/DEVELOPING.md](docs/DEVELOPING.md).

## Licence

LGPL-3.0-or-later.
