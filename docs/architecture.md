# Architecture

A map of the code for someone about to change it. It says where things live
and why they are split the way they are; the module docstrings say the rest,
and the [developing guide](DEVELOPING.md) has the rules every change follows.

## The three packages

| Package | What it is |
| --- | --- |
| `xgfalclient` | The implementation: the context, the plugins, the copy pipeline, the CLI, the in-process test servers. |
| `gfal2` | `import gfal2`, answered by xgfalclient: one module (`src/gfal2/__init__.py`) that replaces itself with the API `xgfalclient._gfal2_module()` builds, carrying python3-gfal2's `__version__`. `xgfalclient.install_as_gfal2()` installs the same object. |
| `gfal2_util` | gfal2-util 1.9.1's importable package (`base`, `shell`, `commands`, ...) for wrappers that run `gfal-*` commands in-process; every command behind it is `xgfalclient.cli`'s. |

`xgfalclient` is built on three libraries - `xrdcore`, `xrdsec` and
`xrdhttp` (`>=0.4.0,<0.5`) - and depends on `xrdclient` (pinned exactly) for
`root://` alone; none of them imports `xgfalclient`. See
[Built on the libraries](#built-on-the-libraries) and
[How xgfalclient uses xrdclient](#how-xgfalclient-uses-xrdclient).

## How a call flows

Every gfal2 call names a URL, and the work is always the same four hops:

```text
user code / gfal-* command
  -> Gfal2Context            (context.py)      the bindings' API, overloads, return codes
    -> plugin registry       (plugins/__init__.py)  which plugin, imported on first use
      -> Plugin subclass     (plugins/<proto>)  the protocol, gfal2's behaviour and wording
        -> wire code         plugin's own client modules, xrdhttp / xrdsec, or xrdclient
```

1. **`Gfal2Context`** (`context.py`) is what programs are written against.
   Each public method (listed in `_API`) is wrapped so a freed context
   refuses it with `EFAULT` and `bytes` arguments are decoded. It parses
   gfal2's overloads, fills the gaps gfal2's core fills itself (`listdir`
   from `opendir`, `mkdir_rec` from `mkdir`, bulk `unlink` from single ones,
   the `user.checksum.*` xattr from `checksum`), then calls
   `plugin(url, operation)` and runs the plugin method through `_guard`.
   `_guard` counts the call as running (for `cancel()`) and turns *any*
   exception into a `GError` with an `errno`.
   The tape (`bring_online` and friends), QoS and `token_retrieve` methods
   are inherited from `StagingMixin` in `_staging.py`, and the handles
   `ctx.open`/`ctx.opendir` return (`FileType`, `DirectoryType`) are in
   `_handles.py`; both are re-exported from `context.py`.
2. **The registry** (`plugins/__init__.py`) lists every built-in as an
   `Entry` - module, class, schemes, priority - so a URL is routed without
   importing anything. A plugin module is imported the first time a URL of
   its scheme needs it; third-party plugins come from the
   `xgfalclient.plugins` entry-point group. Priorities follow gfal2: http,
   lfc, srm, mock, xrootd, gridftp, sftp, file, dcap.
3. **A plugin** (`plugin.py` is the contract) subclasses `Plugin`, sets
   `name` and `schemes`, and overrides the operations it can do. An
   operation left alone is one it cannot do: the context sees the method
   was not overridden and asks the next plugin, ending in `EPROTONOSUPPORT`
   as gfal2 does. A plugin raises `GError(message, errno)`; return values
   are Python values and the context adds gfal2's C-shaped codes.
4. **Copies** go through `transfer.py` instead of a single plugin method.
   `run_copy`/`run_bulk` narrate gfal2's event sequence (checksums,
   overwrite, transfer, cleanup) and either hand the pair to a plugin that
   claims it in `copy_check` (third-party copies, single-request uploads)
   or stream it themselves: `_stream.py` holds `stream` (open both ends
   through their plugins), `pump` (the reader-thread pipeline, which is
   `xrdcore.pipeline`) and `copy_range` (the Linux
   `copy_file_range` fast path between two local files). `transfer.py`
   re-exports all three and owns the tunables tests patch
   (`MONITOR_INTERVAL`, `STREAM_MONITOR_INTERVAL`).

Around that core:

| Module | Role |
| --- | --- |
| `options.py` | gfal2's configuration: `/etc/gfal2.d/*.conf` and `$GFAL_CONFIG_DIR`, read as GLib reads a key file; `get_opt_*`/`set_opt_*`. |
| `creds.py` | `cred_set`/`cred_get` (the URL-prefix credential store) and the gfal2 boundary over xrdsec: gfal2's X.509 search order (`xrdsec.discovery.GFAL2_SEED` for seeding, `GFAL2` for presenting), WLCG bearer-token discovery (`xrdsec.credentials.find_bearer_token(skip_unreadable=True)`; see [Security](security.md#bearer-token-files)), the CA path, JWT expiry (`xrdsec.tokens`) and TLS contexts (`xrdsec.tls.client_context(x509_strict=False)`), with every library error turned into gfal2's `GError`. |
| `errors.py` | `GError` and the helpers that map `OSError`, HTTP statuses and protocol codes to an `errno`. |
| `events.py`, `enums.py`, `types.py` | Copy events, the bindings' integer enums, and the records (`Stat`, `Dirent`, `TransferParameters`). |
| `url.py`, `checksum.py` | URL parsing without normalisation; gfal2's checksum names and comparison over `xrdcore.checksum`. |
| `_log.py` | The `gfal2` logger and `set_verbose`. |
| `_libc.py`, `_xml.py` | `readdir` order through libc; a `sys.modules` alias of `xrdcore.safexml`, the declaration-rejecting XML loader (xgfal's own modules import xrdcore directly). The TLS peer-chain shim `_compat.py` held is `xrdsec.gsi.gss.peer_chain_der` since 0.4.0. |
| `cli/` | The `gfal-*` commands (gfal2-util 1.9.1): `_base.py` is the shared machinery (arguments, context set-up, output through `xrdcore.report`), one module per command family (`_ls`, `_copy`, `_rm`, `_tape`, `_legacy`, `_commands`). |

## Where each protocol lives

| Schemes | Package | Layout |
| --- | --- | --- |
| `http(s)`, `dav(s)`, `s3(s)`, `gcloud(s)`, `swift(s)`, `cs3(s)`, `*+3rd` | `plugins/http/` | `plugin.py` is the plugin; the private modules are one concern each (the client - gfal2's credentials, headers and davix's redirect rule over xrdhttp's shared `session` - WebDAV, third-party copy, S3/GCS/Swift, tape REST, QoS, tokens, delegation, metalink, I/O). The protocol pieces under it are xrdhttp's: the pooled session (`session`, over `engine`, `connection`, `expect`, `wire`), the redirect policy (`redirects`: davix's credential-forwarding rule, a relative `Location` kept in its gfal scheme), multistatus parsing (`webdav`), the tape vocabulary (`tape`), TPC markers and far-side token rules (`tpc`), metalink (`metalink`, under davix's `MetalinkPolicy`) and S3 (`s3.sigv4`, `s3.codec`). |
| `root`, `roots`, `xroot`, `xroots` | `plugins/xrootd/` | A thin layer over xrdclient's public client API: gfal2's errno mapping (`errors`), stat shape (`stat`), xattrs and namespace (`plugin`), copies (`copy`, `tpc`) and staging (`tape`) on top of xrdclient's protocol, sessions and bulk data plane. |
| `gsiftp`, `ftp` | `plugins/gridftp/` | `plugin.py` (facade, namespace operations) over `_base.py` (sessions, pooling, stat), `_copy.py` (third-party and bulk copies) and `_files.py` (open/read/write handles); `control.py` is one logged-in control channel (cleartext or GSI), `data.py` the data channels (MODE S and E), `protocol.py` the wire without sockets (replies, addresses, facts) and `gsi.py` the data-channel TLS contexts. |
| `srm` | `plugins/srm/` | `plugin.py` (facade, namespace, listing, `open`) over `_base.py` (TURL requests and shared helpers), `_staging.py` (bring-online, release, abort, archive poll) and `_copy.py` (TURL-to-TURL copies); `client.py`/`soap.py`/`transport.py` are SRM v2.2 over httpg, `bdii.py` the endpoint discovery over LDAP. |
| `lfc`, `lfn`, `guid` | `plugins/lfc/` | `plugin.py` over `client.py` (the Cns protocol), `wire.py` (framing) and `csec.py` (Csec authentication). Replicas are resolved and the bytes handed to the replica's plugin. |
| `sftp` | `plugins/sftp/` | `plugin.py` picks a transport tier: OpenSSH (`openssh.py`, the system `ssh` client speaking SFTP over its pipes), paramiko (`paramiko_tier.py`, the preferred in-process one) or the built-in SSH-2 client (`ssh.py`, the last resort); `client.py`/`protocol.py` are the SFTP protocol over any of them. |
| `dcap`, `gsidcap`, `kdcap` | `plugins/dcap/` | `plugin.py` over the control line and its per-door pool (`control.py`), the wire format (`protocol.py`), the pool mover's data channel and the open file built on it (`file.py`), and the authentication tunnels (`tunnel.py`: GSI, and Kerberos for `kdcap`). |
| `file` | `plugins/file.py` | The local filesystem, as gfal2's file plugin behaves. |
| `mock` | `plugins/mock.py` | gfal2's mock plugin: a storage element described by its URL, for tests and examples. |

Security code that is not a protocol lives in `crypto/`: proxy delegation
for gridsite (`proxy.py`), X.509 models
(`x509.py`), VOMS (`voms.py`), SSH keys and `known_hosts` (`sshkeys.py`),
SSH ciphers (`ciphers.py`, `chacha.py`, `x25519.py`, `bcrypt.py`) and
Kerberos (`krb5.py`: gfal2's errors and backend choice over xrdsec's
`xrdsec.krb5.gss` and its pure-Python cache reader). The DER, RSA,
AES, Ed25519, P-256 and VOMS modules there are `sys.modules` aliases of
xrdsec's; `x509.py` keeps gfal2's certificate and credential view over
`xrdsec.x509`, and `proxy.py` signs delegations with `xrdsec.proxies`'
`globus` profile.

### The split-module pattern

Several large modules are a public *facade* over private modules
(`plugins/gridftp/plugin.py`, `plugins/srm/plugin.py`, `context.py`,
`transfer.py`, and the test servers below). The rules are the same
everywhere:

* the public module keeps every name it ever had, re-exported with a
  redundant `as` (`from ._copy import _Bulk as _Bulk`) so mypy's strict
  re-export check and ruff treat it as that module's own;
* a plugin class is assembled from mixins (`GridFTPPlugin(_CopyMixin,
  _FilesMixin)`, `SRMPlugin(_StagingMixin, _CopyMixin)`, `Gfal2Context(StagingMixin)`),
  so every method is still the class's, for `help()`, IDEs and subclasses;
* a module attribute that tests (or users) patch stays defined in the
  facade, and moved code that reads it looks it up *through the facade at
  call time* (`from . import transfer as _facade; _facade.STREAM_MONITOR_INTERVAL`),
  so `monkeypatch.setattr("xgfalclient.transfer.X", ...)` keeps working.
  Each facade's docstring says which names that applies to.

## The testing servers

`xgfalclient.testing` ships in-process servers so every plugin is tested
over the real wire against loopback, with no Docker and no ambient grid
services. They are part of the package (and of its coverage gate):

| Module | Server |
| --- | --- |
| `testing/webdav.py` | `WebDAVServer`: a thin davix-style preset of xrdhttp's shared fake storage element (`xrdhttp.testing.StorageServer` - WebDAV, HTTP-TPC, S3/GCS/Swift, tape REST, CDMI, macaroons and tokens, injectable faults) over a `DirectoryStore`, plus the gridsite delegation service it plugs in (X.509, so it stays here). |
| `testing/gridftp.py` (+ `testing/_gridftp/`) | `GridFTPServer`: `ftp://` or `gsiftp://` (GSI with delegation), globus-gridftp-server's replies, MODE S/E data channels. |
| `testing/srm.py` (+ `testing/_srm/`) | `SRMServer`: SRM v2.2 over httpg - namespace, get/put/bring-online requests, space tokens - serving a local directory. |
| `testing/lfc.py` (+ `testing/_lfc/`) | `LFCServer`: Csec, the Cns protocol, an in-memory catalogue. |
| `testing/sftp.py` (+ `testing/_sftp/`) | `SFTPServer` (the SFTP subsystem over any byte stream), `SSHServer` (SFTP over SSH-2, with strict KEX) and a fake `ssh` for the OpenSSH tier. |
| `testing/dcap.py` | `DcapServer`: a dcap door, its pool mover and lister. |
| `testing/ldap.py` | `BDIIServer`: the slice of LDAPv3 SRM endpoint discovery uses. |
| `testing/pki.py`, `testing/_keys.py` | The throwaway grid PKI and frozen RSA keys, in xgfalclient's types and `/DC=org/DC=xgfal` names: a subclass of `xrdsec.testing.pki.BasePKI`, and its key table. |

`root://` is tested against xrdclient's own test server
(`xrdclient.testing`). The larger servers are a public facade over a private
`testing/_<proto>/` package, split the same way as the plugins above: a
model (requests, faults, catalogue entries), the wire or session layer, and
the handlers as mixins or a handler table (`_HANDLERS`, which tests patch
with `monkeypatch.setitem` - it is the same dict the facade exports).

Every test is hermetic: `tests/conftest.py` loads xrdsec's pytest plugin
(`pytest_plugins = ["xrdsec.testing.fixtures"]`), which clears every
`X509_*`, `BEARER_TOKEN*` and `KRB5*` variable, gives each test an empty
`HOME` and points `xrdsec.credentials.TMP_DIR` (where `/tmp/x509up_u<uid>`
and `/tmp/bt_u<uid>` are looked for) and `GRID_SECURITY_DIRS` at directories
of its own; the conftest's `pytest_xrdsec_hermetic` hook adds xgfal's part -
no site configuration (`GFAL_CONFIG_DIR`), no S3 keys or backend selectors. Tests that need a real server are marked
`@pytest.mark.interop` and run only with `XGFAL_INTEROP=1`.

## The gates

Every change passes, locally and in CI (`.github/workflows/ci.yml`):

| Gate | Command | Rule |
| --- | --- | --- |
| Lint | `ruff check src tests benchmarks` | the shared rule set, including the enabled security rules; `ignore = []`, no per-file ignores |
| Format | `ruff format --check src tests benchmarks` | |
| Types | `mypy` | strict, over `xgfalclient`, `gfal2`, `gfal2_util`, the tests and the benchmarks |
| Complexity | `complexipy` | cognitive complexity at most 15 for every function; no snapshot, no ignore markers |
| Coverage | `pytest -n 8 -m "not interop" --cov` | 100% line *and* branch over `src/xgfalclient`; warnings are errors (`filterwarnings = ["error"]`) |
| Conditions | `XGFAL_CONDCOV=1 pytest -n 8 -m "not interop"` | `tests/condcov.py` rewrites the package on import; every `and`/`or` operand, ternary and comprehension `if` must go both ways (also over the library modules listed in `SHARED_MODULES` - why those, its comment says) |
| Import cost | `tests/test_import_cost.py` | `import gfal2` imports no xrdclient or library module; a `gfal-*` command imports `xrdcore.report` and the credential search, never TLS, X.509 or xrdclient; a `file://` call imports no HTTP stack |
| Docs | `mkdocs build --strict` | |

See [Developing](DEVELOPING.md) for the full rules and [Releasing](releasing.md)
for the release checklist.

## Built on the libraries

Since 0.4.0 the code xgfalclient used to share with xrdclient - or carry a
copy of - lives in three libraries, each with its own 100 % line-and-branch
suite, and xgfalclient imports them directly:

| Library | What xgfalclient takes from it |
| --- | --- |
| `xrdcore` | `safexml` (every XML document: WebDAV, SRM SOAP, BDII, metalink, S3), `checksum`/`crc32c` (under gfal2's algorithm names), `pipeline` (`pump`, `ReadAhead`), `report` (the `gfal-*` `--json`/`--xml` document) and `errors` (what the other two raise). |
| `xrdsec` | `gsi.gss` (Globus GSI as a GSS-API mechanism: GridFTP, LFC Csec, dcap, SRM; aliased as `crypto.gsi`), `gsi.httpg` (SRM's httpg connection), `der`, `rsa`, `aes`, `ed25519`, `p256`, `voms` (aliased as `xgfalclient.crypto.*`), `x509` (decoding, proxy rules, the certificate building blocks that moved there from here), `delegation` (request parsing, `issue_certificate`), `proxies` (the `globus` profile: `globus_gsi_proxy_sign_req`, which moved there from `crypto/proxy.py`), `discovery` (`GFAL2`, `GFAL2_SEED`), `credentials` (private-file reading, the token search), `tokens` (JWT claims), `tls` (`client_context`, with `x509_strict=False` and GSI's `check_hostname=False`), and `testing.pki`/`testing.https`/`testing.gsi` (the GSI acceptor side: token loops, the httpg preamble) for the test servers. |
| `xrdhttp` | `session`, `engine`, `connection`, `expect`, `wire`, `redirects`, `webdav`, `tape`, `tpc`, `metalink`, `s3.sigv4`, `s3.codec`: everything below the HTTP plugin's gfal2 wording. |

What stays in xgfalclient is gfal2's behaviour on top: option names and
precedence, the credential store, davix's status words and errno values
(`plugins/http/_status.py`), the Tape REST requests and messages gfal2 sends
(xrdhttp's `TapeClient` roots requests at `/api/v1` as XrdClHttp does, where
gfal2 uses the URI the discovery document names), the TPC headers only davix
sends, and the types the plugins and tests are written against
(`crypto.x509.Certificate`/`Credential`, `testing.pki.PKI`). Library errors are
turned into `GError` where xgfalclient calls the library, never later.

The old module paths that were aliases of xrdclient's (`_xml`,
`crypto.{aes,der,ed25519,p256,rsa,voms}`, `plugins/http/_connection`) are now
`sys.modules` aliases of the library modules, so a test that patches one
patches what the code calls (`tests/test_shared_core.py`); so is
`crypto.gsi`, of `xrdsec.gsi.gss`, since GSI moved there.

## How xgfalclient uses xrdclient

The dependency is one-way and pinned to an exact release (`xrdclient==0.4.0`),
because the two are released together. Since 0.4.0 xgfalclient takes only
what is genuinely xrdclient's - the XRootD client:

* **`root://`**: `plugins/xrootd/` drives xrdclient's client through its
  public API (file and filesystem operations, `abort()`, the bulk data
  plane, `File.write_pieces`, `client.bulk`) and translates its results and
  errors (`xrdclient.errors`) into gfal2's. Its copies read ahead with
  `xrdcore.pipeline.ReadAhead`, the same pipeline xrdclient's copy engine uses.
* **Tests**: `root://` is tested against xrdclient's own test server
  (`xrdclient.testing`), and `tests/conftest.py`'s hermetic hook points xrdclient's
  Config-shaped token search (`xrdclient._tokens.TMP_DIR`) at the same empty
  directory as xrdsec's.

xrdclient's package is lazy (PEP 562), so the XRootD plugin pulls in only
what it needs, and nothing else in xgfalclient imports xrdclient at all;
`tests/test_import_cost.py` checks the result. A change to shared code is
tested in its library and in every client - see
[Developing: shared core ownership](DEVELOPING.md#shared-core-ownership).
