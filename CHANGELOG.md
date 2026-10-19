# Changelog

Notable user-visible changes are recorded here. The `xgfalclient` version is
independent of the gfal2 and python3-gfal2 compatibility versions reported by
the replacement API.

## [0.4.0] - Unreleased

### Code health

- A banned-API lint (ruff `TID251`, `[tool.ruff.lint.flake8-tidy-imports.banned-api]`)
  refuses, in `src` and `tests` alike, what the libraries own: `http.client`
  and third-party HTTP stacks (use `xrdhttp.session`/`xrdhttp.connection`),
  `gssapi`/`krb5` (`xrdsec.krb5`), hand-built TLS contexts (`xrdsec.tls`,
  `xrdsec.gsi.gss.data_contexts`, `xrdsec.testing.pki.PKI.client_context`),
  `ThreadPoolExecutor` (`xrdcore.fanout`), the XML parsers
  (`xrdcore.safexml`), `botocore`/`boto3` (`xrdhttp.s3`), and xrdarc/xrdwms.
  No per-file ignore, no `noqa`; CONTRIBUTING.md lists each entry and why.
  To get there: GridFTP's `DCAU` context pair (`data_contexts`, with its
  cache) moved to `xrdsec.gsi.gss.data_contexts` and is re-exported from
  `plugins.gridftp.gsi` under its old name; the http plugin, its error
  mapping and the SRM transport name `IncompleteRead`, `HTTPException` and
  `HTTPResponse` through `xrdhttp.connection`; the tests take their TLS
  contexts from `PKI.client_context` / `xrdsec.tls.client_context`, their
  `http.client` types and connections from `xrdhttp.connection`, and parse
  XML with `xrdcore.safexml`. The duplicated `data_contexts` caching test
  went with the code (xrdsec's suite covers it).
- The HTTP behaviour the http plugin shares with every client of a storage
  element is tested by xrdhttp's conformance suites
  (`xrdhttp.testing.conformance`), run in `tests/test_http_conformance.py`
  through `GfalAdapter`/`GfalS3Adapter` - the gfal2 calls a user makes
  (`stat`, `listdir`, `open`, `checksum`, `filecopy` in one `3rd pull`/`3rd
  push` mode, `bring_online`, `token_retrieve`, S3 through `s3://`) - the
  same suites xrdclient runs through its own API. The 11 tests they replace
  were deleted from `test_http_io.py` (4), `test_http_client.py` (3),
  `test_http_copy.py` (2), `test_http_edges.py` and `test_http_s3.py` (1
  each), and nine more were cut down to their gfal2-only assertions (davix's
  errno and wording, `Want-Digest` as given, `opendir`'s stat, `mkdir_rec`
  over a file, `creationdate`); what stays tests gfal2's own promises.
- `tests/conftest.py` loads xrdsec's `xrdsec.testing.fixtures` plugin
  (the hermetic environment, `pki`, `grid_env`) instead of its own copy;
  its `pytest_xrdsec_hermetic` hook keeps gfal2's own part (`GFAL_CONFIG_DIR`
  with a closed BDII, S3 keys, backend selectors, `xrdclient._tokens.TMP_DIR`),
  and its `pki` stays xgfal's typed view. The tests no longer see the
  host's `/etc/grid-security` or Kerberos cache.
- `-v` logging is `xrdcore.log.configure` (the handler was built here):
  the same gfal2-util scale, stdout or `--log-file` (still truncated), and
  `LEVEL message` format, now redacting what it writes. A `--log-file` that
  cannot be opened leaves the library verbosity untouched. The end of a
  command keeps gfal2-util's own reporting (errno exit statuses, `EINTR`
  after Ctrl-C, "Run with -vvv"), so `xrdcore.cli.Fatal`/`run` are not used.
- No grandfathered code: the Complexipy snapshot is gone and every function
  is at most 15; Ruff runs the shared rule set (now with `C4`) with no
  ignores or per-file ignores; `mypy --strict` covers the tests too; pytest
  turns every warning into an error (the socket leaks that hid behind it
  are fixed); suppression comments were replaced by typed code, and the few
  irreducible ones carry a reason. Deprecated names remain only where they
  mirror gfal2, python3-gfal2 or gfal2-util, and their docstrings say so.
- `TransferParameters.set_checksum` is typed to take `None` for the
  algorithm and value, as python3-gfal2's callers pass it (it always did).
- `import gfal2` has a type stub (`gfal2/__init__.pyi`) naming what the
  self-replacing module holds.
- The built-in Python SSH transport for `sftp://` (`TRANSPORT=python`) is a
  supported last-resort tier, not a deprecated one: it is what lets a base
  install (no paramiko, no `ssh`, or a password) reach an SFTP server as
  gfal2's libssh2 plugin does, and the in-process test server is built on
  it. It no longer emits a `DeprecationWarning`.
- Tests: the BRIX harnesses are xrdclient's public `xrdclient.testing.brix`
  (`tests/_brix.py` and `tests/_brix_fs.py` are gone), and the DER, Ed25519 and P-256 cases that
  re-tested xrdsec's own modules (`test_crypto.py`, `test_sftp_crypto.py`) were
  removed - xrdsec's suite holds every one of them; condition coverage
  (`tests/condcov.py`) leaves `xrdsec.der` and `xrdsec.p256` to xrdsec's gate,
  since only those copies reached their malformed-input decisions.
- Tests: the BRIX FUSE fault scenarios of `test_brix_fault_fs.py` (short and
  zero-progress I/O, early and late `ENOSPC`, torn and dropped writes,
  dishonest and failing `fsync`, stale and replaced sources, a lying size,
  stable storage) are xrdclient's shared `xrdclient.testing.brix`
  `LocalCopySuite`, run here through a `Gfal2Context.filecopy` adapter;
  only gfal2's own errno and wording (`Short copy`, `DESTINATION CHECKSUM
  MISMATCH` as `EIO`, the stale-splice message) stay as overrides. The
  short-I/O case now also verifies the copy's checksum.
- Tests: the safe-XML cases of `test_portable_parsers.py` that re-tested
  `xrdcore.safexml` itself (every encoding, both ElementTree parsers, the
  hostile documents) were removed - xrdcore's suite holds each of them; what
  stays is how each xgfal protocol reports the refusal. The report tests
  read documents with `xrdcore.report.parse`, the GridFTP GSI tests run
  their exchanges with `xrdsec.testing.gsi.exchange_tokens`, and the dcap
  fake reads frames with `xrdcore.sockets.recv_exact` (a hang-up is
  `ShortRead`, an `OSError`, which ends the mover as `EOFError` did).
- Release metadata is xrd-devtools' release gate:
  `tests/test_release_metadata.py` replaces its own checks with `release_gate(__file__)` from
  `xrddevtools.pytest_plugin` - one version source (`_version.py`, read by
  hatch), a CHANGELOG led by exactly that version's well-formed section,
  project metadata and README that name this repository, and a release
  workflow built through the shared publish action.
  Only `VERSION == __version__` (python3-gfal2's spelling) stays here; the
  `site/` ignore check is the gate's (for every repository with a site).
- The publish workflow's build job is xrd-devtools' shared `publish`
  composite action (build, `twine check --strict`, the artifact or
  pre-flight checks, the gfal2 compatibility-version check, a clean install whose tag, runtime version and dated
  changelog section agree, the artifact upload); only the trusted-publishing
  upload to PyPI stays in this workflow's own job.
- The standard's settings in `pyproject.toml` (ruff rules, the banned-API
  table, mypy's strictness and allowed overrides, complexipy, coverage,
  pytest's warnings filter) and CONTRIBUTING's *The code standard*, *Banned
  APIs* table and *xrd-devtools* sections are managed blocks, written by
  `xrddevtools sync` from the standard kept once in xrd-devtools;
  `xrddevtools conformance` fails a hand edit between the markers. The
  repository's own keys and notes sit beside the blocks.
- Banned-API messages for importing a package of the chain built on this
  one now say so ("sits below ... dependency direction"), generated from the
  declared layering.

### Built on xrdcore, xrdsec and xrdhttp (what moved where)

xgfalclient now depends on the three shared libraries directly
(`xrdcore>=0.4.0,<0.5`, `xrdsec>=0.4.0,<0.5`, `xrdhttp>=0.4.0,<0.5`), and on
`xrdclient==0.4.0` only for `root://`. Every public name - xgfalclient's,
`gfal2`'s and `gfal2_util`'s - behaves as before; the semi-public
`xgfalclient.crypto.*` paths remain. Map in `docs/architecture.md` and
`docs/DEVELOPING.md`.

- **The HTTP transport is xrdhttp's shared session.** `plugins/http/_client.py`
  (1025 -> 567 lines) keeps gfal2's policy - credentials (`get_credentials`'s
  order), standing headers, davix's quoting and `Authorization`-forwarding
  rule, `[HTTP PLUGIN] KEEP_ALIVE`/`INSECURE`, `cancel()` registration, the
  S3/GCS/Swift signers - over `xrdhttp.session.Session`, which now does the
  pooling (per endpoint and TLS context), the stale-connection replay, the
  redirect loop, `Expect: 100-continue`, direct socket reads and `sendfile`
  bodies for xrdclient and xrdarc too. `Response` and `FileBody` are
  xrdhttp's objects; `Upload` is a thin wrapper keeping gfal2's `EFBIG`/`EIO`
  wording. Behaviour is unchanged except: `Response.read(n)` on a body cut
  short raises `ECOMM` at once instead of first returning `b""`.
- **The test WebDAV server is xrdhttp's.** `testing.webdav.WebDAVServer` is
  now a thin davix-style preset of `xrdhttp.testing.StorageServer`, the fake
  storage element xrdclient's suite runs against too; `testing/_webdav/*`
  (the handler, WebDAV, TPC, tape/CDMI, tokens, S3/GCS/Swift mixins) is
  gone. `S3`, `Swift`, `Tape`, `Fault` and `Request` are xrdhttp's objects.
  What stays here is what needs X.509: the gridsite delegation service
  (delegation 1 and 2), plugged in as the server's `delegation_service`.
  Differences a test sees: `Request` and `Fault` are xrdsec's generic test
  server's (the storage element is built on it): a request's wire form is
  `.target` (`.path` is the decoded path) and its client certificate
  `.peer`; a fault's `stall=` (go silent) is `hold=`, and without a
  `status` it now acts on the real answer, so a fault that must answer with
  its own body says `status=200`; `redirects` is one-shot by exact path and the old
  persistent prefix map is `redirect_prefixes`; `send_continue`,
  `ignore_range` and `webdav = False` are `expect_continue`,
  `ignore_ranges` and `no_dav = True`; `tpc = "fail"` is
  `tpc_failure = "<text>"`; tape errors are JSON (`{"message": ...}`), ids
  are `stage-0001`..., and a default `Tape()`'s site is `fake-site`; an S3
  `PUT` answers `200` (as S3 does) and S3 errors are `<Error><Code>`
  documents; a collection's `href` ends in `/` and is percent-encoded once.
  The fake's own corner cases moved to xrdhttp's suite.
- **Aliases now of the libraries** (`sys.modules`, the same module objects):
  `xgfalclient.crypto.{aes,der,ed25519,p256,rsa,voms}` are `xrdsec.*`,
  `xgfalclient._xml` is `xrdcore.safexml`, `plugins.http._connection` is
  `xrdhttp.connection` (they were xrdclient's aliases of the same code).
- **Credential discovery and TLS** (`creds`): gfal2's X.509 search orders
  are `xrdsec.discovery.GFAL2_SEED` (what a context seeds) and `GFAL2` (what
  a plugin presents); bearer-token discovery is
  `xrdsec.credentials.find_bearer_token(skip_unreadable=True)`; the CA path
  is `xrdsec.discovery.discover_ca_dir`; `token_claims`/`check_bearer_token`
  are over `xrdsec.tokens`; `TLSContexts` is a front of
  `xrdsec.tls.client_context(x509_strict=False)`, whose process-wide cache is
  keyed by each file's `stat`, so a proxy renewed in place is picked up
  without a `cred_set`. Option names, precedence, debug lines and `GError`
  codes and messages are gfal2's as before. The private `creds._uid` and
  `creds.TOKEN_TMP_DIR` are gone (the search uses the effective uid and
  `xrdsec.credentials.TMP_DIR`). A separate private key is now read through
  xrdsec's private-file checks (yours, `0600`) and piped to OpenSSL, as
  xrdclient reads one, so a key others may read fails with `EACCES` and
  `chmod 600` instead of being loaded.
- **Proxy delegation and X.509** (`crypto.proxy`, `crypto.x509`):
  `sign_request` is `xrdsec.proxies.issue_proxy(profile="globus")` - the
  `globus_gsi_proxy_sign_req` policy moved there from this module - with
  every refusal still a `DERError`; it now also never dates a proxy before
  its issuer and carries a signer's path-length limit down. The building
  blocks `extension`, `key_usage`, `public_key_info` and
  `signature_algorithm` moved to `xrdsec.x509` and are re-exported here;
  `build_certificate` is `xrdsec.delegation.issue_certificate` itself;
  `proxy_cert_info` is xrdsec's encoding. The private aliases `_decode_name`,
  `_extensions`, `_policy_language` and the unused `proxy_serial` are gone
  (xrdsec's public `name_from_element`, `tbs_extensions`, `policy_language`).
- **HTTP plugin**: the redirect policy is xrdhttp's - davix's
  credential-forwarding rule is `xrdhttp.redirects.davix_carries_credentials`
  (moved there from `_target._may_forward`) and a relative `Location` is
  `resolve_location`, which keeps the gfal scheme as `_target._resolve` did;
  the engine, wire, expect, WebDAV, metalink, tape vocabulary (`WELL_KNOWN`
  included), TPC marker reader and far-side token rules (`token_minutes`,
  the activity sets) and S3 SigV4/codec are imported from xrdhttp, not
  through xrdclient's aliases. gfal2's Tape REST requests and wording stay
  here: xrdhttp's `TapeClient` roots requests at `/api/v1` as XrdClHttp does.
- **Core**: checksums and CRC-32C are `xrdcore.checksum`/`xrdcore.crc32c`
  (`checksum.crc32c_py` is `xrdcore.crc32c.crc32c_py`), the streamed copy and
  the XRootD upload read-ahead are `xrdcore.pipeline`, and the `gfal-*`
  `--json`/`--xml` report is `xrdcore.report` (was `xrdclient.cli._output`):
  a `gfal-*` command no longer imports any xrdclient module.
- **Test support**: `testing.pki.PKI` subclasses `xrdsec.testing.pki.BasePKI`
  (same types and `/DC=org/DC=xgfal` names); `testing._keys` re-exports
  xrdsec's frozen keys; `testing.webdav`'s listener is
  `xrdsec.testing.https.TLSServer`.
- **Tests**: cases that only re-tested moved code were deleted after
  checking the library has them (`test_voms*.py`, most of
  `test_shared_core.py` and `test_shared_engines.py`, the x509 building-block
  cases); the few the libraries lacked moved into xrdsec's and xrdhttp's
  suites. `tests/condcov.py`'s `SHARED_MODULES` names library modules now
  (see its comment), with `tests/test_library_decisions.py` taking their
  non-gfal2 decisions. CI checks out the four candidates
  (xrd-devtools' candidates action) and the interop harnesses bind-mount the
  libraries as well as xrdclient.
- **Dependencies**: `botocore` is no longer a direct dependency (S3 signing
  and parsing are xrdhttp's, whose `s3` extra brings it: the requirement is
  `xrdhttp[s3]>=0.4.0,<0.5`).
- **Thread fan-out and exit codes** (`xrdcore.fanout`, `xrdcore.cli`): the
  parallel ranged HTTP download (`plugins.http._ranged`) runs its segments
  through `xrdcore.fanout.run_all` instead of its own pool and failure
  bookkeeping (private `_record_failure` removed); the commands' quiet
  broken pipe is `xrdcore.cli.silence_stdout` (private
  `cli._base._silence_stdout` removed), and their 0/1 are
  `xrdcore.cli.ExitCode`'s. gfal2-util's errno exit statuses (`EINTR`,
  `ETIMEDOUT`, the `GError` code) are unchanged.
- **Kerberos** (`crypto.krb5`): the GSS-API contexts, the python-gssapi
  backend and the GSS status-to-`errno` mapping moved to `xrdsec.krb5.gss`
  (shared with xrdclient, whose pure-Python Kerberos client is
  `xrdsec.krb5.client`). `crypto.krb5` is now one module keeping gfal2's
  side: `KerberosError` is a `GError` *and* an `xrdsec.krb5.gss.KerberosError`
  (the library's errors are re-raised as it with the same message, `errno`,
  statuses and token), `XGFAL_KRB5_BACKEND` with the `ctypes` alias, `HINT`;
  the flags and `reset` are xrdsec's objects. `inspect_cache()` reads the
  cache with xrdsec's pure-Python reader (`FILE:`, `DIR:`, `KCM:`,
  `KEYRING:`) instead of pykrb5: same dictionary, and a missing cache is now
  `ENOENT` (an unreadable one stays `EACCES`; there is no pykrb5 minor code
  any more). The private `crypto.krb5._base`, `_cache`, `_gssapi` and
  `_status` modules are gone (`xrdsec.krb5.gss`, `xrdsec.krb5.client`,
  `xrdsec.krb5._gssapi`, `xrdsec.krb5._status`), as is the old `Backend`/
  `Mechanism` interface; the test fake GSS-API module is
  `xrdsec.testing.krb5.fake_gssapi_module`.
- **GSI** (`crypto.gsi`, the SRM transport, the fakes): the Globus GSI GSS
  mechanism moved to `xrdsec.gsi.gss` (about 400 lines), and
  `xgfalclient.crypto.gsi` is now that module (`sys.modules` alias, like
  `crypto.aes`). It delegates with any credential that has a `chain` and a
  `key` (this package's `Credential` included); `peer_certificate()` and
  `DelegatedCredential.chain` are `xrdsec.x509.CertificateData` and
  `DelegatedCredential.credential()` an `xrdsec.x509.ProxyCredential` (were
  this package's `Certificate`/`Credential`); `check_host`/`dns_names` take a
  `CertificateData`. The GridFTP, LFC, dcap and SRM plugins import it from
  xrdsec. The SRM transport's `HTTPGConnection`, `Handshake` and
  turn-skipping reply class are `xrdsec.gsi.httpg`'s (the private
  `transport._Response` is gone); pooling, SOAP and srm-ifce's wording stay.
  `crypto.proxy.make_request` is `xrdsec.delegation.make_proxy_request`, and
  `sign_request` a thin adapter over `xrdsec.delegation.sign_globus_request`
  (still `DERError` for every refusal). The fakes' acceptor side is
  `xrdsec.testing.gsi`: the dcap and LFC token loops
  (`acceptor`/`accept_tokens`), LFC's proxy-owner DN (`proxy_owner`; the
  private `testing.lfc._proxy_owner` is gone) and the SRM fake's httpg
  preamble and context shaping (`accept_httpg`, `httpg_context`; a wrong
  delegation flag is now a `GSIError`, still ending only that connection).
  Tests moved with the code: `test_gsi.py`, the `HTTPGConnection` and
  `peer_chain_der` cases and the DER-chain splitting case now run in
  xrdsec's suite.
- Library additions made for this: `xrdsec.tls.client_context(check_hostname=,
  alpn=)` (GSI's own name check) and `xrdsec.proxies.issue_proxy(digest=)`.


### Security

- The built-in SSH transport for `sftp://` implements OpenSSH strict key
  exchange (`kex-strict-c-v00@openssh.com`), closing the Terrapin
  prefix-truncation attack (CVE-2023-48795) against servers that offer it
  (OpenSSH 9.6+): any message other than the key exchange's own during the
  initial exchange is fatal, and sequence numbers restart at every `NEWKEYS`.
- `TRANSPORT=auto` uses paramiko only from 3.4 (its strict-KEX release); an
  older paramiko is passed over.
- `sftp://` `known_hosts` entries for a non-22 port (`[host]:port`) now
  match: the brackets were read as a glob character class, so such hosts were
  always "unknown" and `accept-new` (the default) accepted a changed host key
  on every connection. Only `*` and `?` are wildcards, as in OpenSSH.
- Bearer-token files xgfalclient discovers itself (`$BEARER_TOKEN_FILE`,
  `$XDG_RUNTIME_DIR/bt_u<uid>`, `/tmp/bt_u<uid>`) are now read through
  the shared credential-file reader (xrdsec's, the one `root://` uses), for
  every protocol: a file that is not
  a regular file owned by you with no group/other access fails the operation
  with `EACCES` naming the file and `chmod 600`, instead of being presented.
  A symbolic link at the two predictable names is refused. Previously a
  world-readable or planted `/tmp/bt_u<uid>` was used for `davs://` and the
  other non-`root://` protocols.
- `root://` with a separate certificate and key (`$X509_USER_CERT` and
  `$X509_USER_KEY`, `~/.globus/usercert.pem` and `userkey.pem`, or `[X509]
  CERT`/`KEY`) no longer copies the private key, with the certificate, into
  a temporary file (`xgfal-x509-*.pem`): the two files go to xrdclient as they
  are (`Config.usercert`/`userkey`), which makes what TLS and GSI need in
  memory. The context's choice of credential is always passed explicitly, so
  `$X509_USER_PROXY` no longer overrides it.
- The `sftp://` in-process transports create a missing `~/.ssh` (or the
  `KNOWN_HOSTS` file's directory) mode 0700, as OpenSSH does, when recording
  a first host key; it used to get the umask's mode (typically 0755).

### Added

- `Gfal2Context.abort_on_cancel()` / `register_abort()` / `unregister_abort()`
  (and `Transfer.abort_on_cancel()`): plugins register the socket an
  operation is blocked on, and `cancel()` shuts it down. HTTP, XRootD,
  GridFTP, dCap and SFTP (all three transports) use it.
- `[CORE] CANCEL_TIMEOUT` (seconds, default 10, `0` for no limit): how long
  `cancel()` waits for running operations.
- `copy_file_range(2)` fast path for local `file://` to `file://` copies on
  Linux, falling back to the streamed pipeline where the kernel refuses.
- `sftp://` host and user keys may be `ecdsa-sha2-nistp384` and
  `ecdsa-sha2-nistp521` (RFC 5656) as well as `nistp256`: a server whose only
  host key is P-384 now works with the paramiko and built-in transports, and
  `known_hosts` reads, records and matches such keys.
  `PrivateKey.from_ecdsa(d, comment, kind=...)` picks the curve.
- `crypto.x509.build_certificate` signs with an EC key too
  (`ecdsa-with-SHA*`), so an EC proxy can sign a delegated proxy through
  `crypto.proxy.sign_request`, and certifies any key `cryptography` can load.

### Changed

- `xgfalclient.testing.pki` is now a thin layer over the shared
  `xrdsec.testing.pki` (xrdclient's `testing.pki` is an alias of it): same
  names, types and `/DC=org/DC=xgfal` subjects, plus `crl()`/`install_crl()`;
  `xgfalclient.testing._keys` re-exports the frozen keys.
- Duplicated implementations removed in favour of the shared ones (now the
  libraries', see above), with the
  same import paths, exceptions and gfal2 wording (map in
  `docs/DEVELOPING.md`): CRC-32C and the digests (`checksum`), certificate
  reading and key loading (`crypto.x509`), PKCS#10 parsing
  (`crypto.proxy.parse_request`), WebDAV multistatus/`Digest` parsing,
  Metalink parsing, the Tape REST discovery vocabulary, the TPC
  performance-marker reader, and the HTTP transport's direct socket reads,
  `sendfile`/TLS file sends and idle connection pool.
- `crypto.x509.load_credential` accepts EC keys (an EC proxy signs delegated
  proxies); an Ed25519 or DSA key is a `DERError` naming it.
- `crypto.proxy.parse_request` reads requests for any key type, and
  `CertificateRequest` is xrdclient's `ProxyRequest` (no `digest`, `info`
  or `signature` fields; `verify()` checks any algorithm). A request signed
  with an algorithm the key does not match now parses and fails `verify()`
  (`sign_request` says "does not verify") instead of being refused as
  unsupported; malformed ones say "not a PKCS#10 certificate request".
- `checksum` uses `google-crc32c` only when its C extension is present.
- The http plugin's `_client.py` and `_copy.py` are split by concern
  (`_target`, `_status`; `_copy_common`, `_streamed`, `_ranged`, `_tpc`);
  `_client` and `_copy` re-export what they held.

- Python 3.11 is now the minimum (tested on 3.11 to 3.14; 0.3.1 had raised
  it to 3.10). On AlmaLinux/RHEL 8 and 9 use AppStream `python3.11` or
  `python3.12`; the system Python 3.9 is not supported. 0.3.2 is the last
  release for Python 3.10 (0.3.0 the last to declare 3.9).
- Bearer-token discovery passes over a `$BEARER_TOKEN_FILE` that names a
  missing or blank file and goes on to `$XDG_RUNTIME_DIR/bt_u<uid>` and
  `/tmp/bt_u<uid>`, as xrdclient (and so `root://`) does; it used to stop
  there with no token.
- Internal layout only (no import path or behaviour change): the largest
  modules are now facades over private modules - `plugins/gridftp/plugin.py`
  (`_base`, `_copy`, `_files`), `plugins/srm/plugin.py` (`_base`, `_copy`,
  `_staging`), `context.py` (`_handles`, `_staging`), `transfer.py`
  (`_stream`) and the `testing` servers for WebDAV, LFC, SFTP, GridFTP and
  SRM (`testing/_<proto>/`). Every name stays importable from where it was.
  New `docs/architecture.md` maps the code for maintainers.
- Requires `xrdclient==0.4.0`. Its credential-file rule applies to
  `root://`: a proxy (or SSS keytab, or a bearer-token file it discovers)
  must be a regular file owned by you with mode `0600`, or the login fails
  naming `chmod 600 <path>`.
- `crypto.x509.build_certificate` is now xrdsec's
  `delegation.issue_certificate` (same keywords): SHA-1 signatures are
  refused with `ValueError`, and `serial=None` is a random positive 63-bit
  number, as before. Key loading errors read "unreadable private key: ...".
- S3 requests and pre-signed URLs are signed through xrdhttp's public
  `s3.sigv4.sign`/`presign` (signatures unchanged), no longer botocore's
  private signer state.
- The HTTP plugin pools its standard-library connections itself instead of
  through `urllib3`'s private pool methods (same per-endpoint limit of 16
  idle connections, newest reused first).
- SSH ECDSA and Ed25519 keys use `cryptography` directly rather than
  xrdclient's `p256`/`ed25519` modules (`xgfalclient.crypto.p256` and
  `.ed25519` remain as aliases). ECDSA signatures are randomised rather than
  RFC 6979-deterministic; both verify the same.
- Bearer-token expiry diagnostics decode the JWT with a strict standard-library
  base64url/JSON reader: padding, the standard base64 alphabet, whitespace,
  non-UTF-8 or non-object segments now mean "no claims" (an opaque token)
  rather than being decoded leniently. Tokens are still never verified.
- Passphrase-protected OpenSSH private keys are decrypted with pyca `bcrypt`
  (new base dependency `bcrypt>=4`): an `ssh-keygen` default key now loads in
  a fraction of a second instead of about a minute. The pure-Python
  Blowfish/`bcrypt_pbkdf` is gone; `xgfalclient.crypto.bcrypt.bcrypt_pbkdf`
  remains as a wrapper (its `bcrypt_hash`/`pi_words` internals are removed).
- `sftp://` `TRANSPORT=auto` order is OpenSSH (no password), then paramiko,
  then the built-in transport. New `sftp` extra: `pip install
  'xgfalclient[sftp]'` installs paramiko.
- The paramiko tier passes a key passphrase as bytes (paramiko's loader
  rejected a `str`), and a key paramiko cannot load falls back to the password.
- Faster start-up: `import gfal2` no longer imports xrdclient (the copy
  pipeline is imported when a copy first streams), and the HTTP plugin
  imports botocore only for `s3://` and its RSA/X.509 stack only for
  `gcloud://` or proxy delegation.
- A parallel HTTP download runs on a thread pool: the first failing segment
  cancels the queued ones, and other streams' failures are attached to the
  reported error as notes (same error type and code).
- The XRootD plugin imports xrdclient directly. `XRootDPlugin.available()` is
  gone (the base class's applies); a broken xrdclient still makes `root://`
  URLs say how to repair the install, now through the plugin registry.
  `xrootd.MISSING_HINT` remains, as `plugins.XROOTD_HINT`.
- The XRootD plugin uses only xrdclient's public API (and the shared
  `xrdcore.pipeline.ReadAhead`): uploads go through `File.write_pieces`,
  listings through `FileSystem.dirlist`, a staging abort through
  `FileSystem.cancel_prepare`, `cancel()` through `File`/`FileSystem.abort()`,
  and a third-party pull's `ofs.tpc cancel` through `File.fcntl` beside the
  waiting sync. Its own rendezvous is kept rather than
  `xrdclient.third_party`, which drops the URLs' CGI (`authz=`, `svcClass`,
  `XRD.*`) and removes an empty destination it refused to overwrite.
  `xgfalclient.plugins.xrootd` is now a package (`plugin`, `errors`, `stat`,
  `file`, `copy`, `tpc`, `tape`, `urls`); every name it offered is still
  importable from it.
- Cancelling a `root://` download or upload - `cancel()`, the copy's timeout,
  a monitor callback that raised - stops it at once: xrdclient aborts the
  handles in flight. A multi-stream download used to notice only between
  chunks, and so waited out a stalled read.
- A third-party pull with no copy timeout (`timeout=0`) waits up to 30
  minutes for the destination (XrdCl's `CPTPCTimeout` default) rather than
  without limit. A reply the destination sends on a stream nobody asked on,
  or a partial one, during a pull no longer fails it with `EPROTO`:
  xrdclient's session passes it over and the pull waits for its answer.

### Removed

- `plugins/http/_connection` (the alias of `xrdhttp.connection`) and the
  HTTP client's private machinery, now `xrdhttp.session`'s: `_Exchange`,
  `_Route`, `_PoolKey`, `_STALE`, `_Early`, `_length`, `_nothing`,
  `HTTPClient._checkout`/`_checkin`/`_perform`/`_start`/`_send_body`/
  `_hop_headers`, and the `DIRECT_READ` re-export (`xrdhttp.wire.DIRECT_READ`).
- `PyJWT`, `asn1crypto`, `urllib3` and `botocore` are no longer direct
  dependencies (`asn1crypto` arrives through `xrdsec`, `botocore` through
  `xrdhttp[s3]`, `urllib3` through `botocore`).
- The Python 3.9/3.10 compatibility shims in `xgfalclient._compat`
  (`SLOTS`, `TIMEOUTS`, `dataclass_slots`; private) and the 3.9 leaf-only
  TLS peer-chain fallback.
- The private `xgfalclient._compat` module: its last function,
  `peer_chain_der`, is `xrdsec.gsi.gss.peer_chain_der`. The private
  `crypto.x509.split_der_certificates` (only GSI used it) is
  `xrdsec.x509.split_der_certificates`, which answers xrdsec's
  `CertificateData`.
- `xgfalclient.plugins.srm.bdii.match_filter` and `decode_filter`, which only
  the test BDII used, moved to `xgfalclient.testing.ldap`.
- Private aliases nothing used: `xgfalclient.testing.sftp`'s `_stat`,
  `_ciphers`, `_x25519`, `_ssh`, `GError_` and `fx`;
  `testing.gridftp._stat` and `testing.srm._stat`; and the gridftp plugin
  module's `_stat`, `urllib` and `ev` (import the real modules instead).
- pykrb5 (`krb5`) from the `krb5` extra, which is now `xrdsec[krb5]`
  (python-gssapi); cache diagnostics no longer need a native binding.
- The empty `xrootd` extra, a compatibility alias since `root://` support
  joined the base install: use `pip install xgfalclient` (an `[xrootd]`
  request now only draws pip's unknown-extra warning).

### Fixed

- `s3://`: a streamed upload (`open(O_WRONLY)` with a size) signed its head
  with the hash of an empty body, which S3 refuses once the bytes arrive
  (`XAmzContentSHA256Mismatch`); it is now signed `UNSIGNED-PAYLOAD`, as a
  `sendfile` body already was. The shared fake checks the payload hash for
  xgfalclient's tests too.
- `srm://`: a GSI name check that refuses the server (or a failed
  delegation flag) no longer leaves the TLS socket open: the raw socket was
  closed, but TLS had already taken it over.
- `gsiftp://`/`ftp://`: data connections are closed when a transfer
  finishes; they were closed only on failure and otherwise left to the
  garbage collector.
- An XRootD upload whose connection closes under it is still reported as
  gfal2's lost connection now that xrdclient raises `ConnectionError` (not
  `TimeoutError`) for it.
- `cancel()` no longer waits for the full operation timeout (300 s by
  default) when an operation is blocked on a server that stopped sending:
  the operation fails with `ECANCELED` at once.
- A cancelled streamed copy now removes its partial destination, as the
  documentation says: calls a running operation makes for itself are no
  longer refused while the cancel drains.
- Closing an `sftp://` file whose session has died (cancelled, or lost) no
  longer fails a second time: the handle went with the session.
- `sftp://`: a read answered with a status (end of file, or an error) no
  longer leaves the caller's buffer registered in the client, where it pinned
  the buffer and, once request ids wrapped, could receive a later request's
  data.
- `sftp://`: a file whose buffered writes fail now still sends `CLOSE`, so the
  server does not keep the handle open for the life of the pooled session.
- `sftp://`: `pwrite` on a file opened for reading and writing splits its data
  at the server's `max_write`, rather than sending one `WRITE` a server may
  refuse or drop the session over.
- `sftp://`: the session pool is bounded: at most `[SFTP PLUGIN] MAX_IDLE`
  idle sessions per endpoint (default 4; 0 disables pooling), and none kept
  idle longer than `MAX_IDLE_SECONDS` (default 60; 0 for no limit).
- `sftp://` (built-in transport): a truncated message from the server after
  the handshake fails every waiting call with `EPROTO`; it used to end the
  reader thread silently and leave them blocked. A bad curve25519 public
  value from the server is `EPROTO` too, not a bare `ValueError`.
- `sftp://` (OpenSSH transport): `[SFTP PLUGIN] SSH_OPTIONS` now override the
  plugin's own defaults (`ConnectTimeout`, `StrictHostKeyChecking`,
  `UserKnownHostsFile`, `LogLevel`, the `ServerAlive` probes): ssh keeps the
  first value of an option, and they used to come after ours. `BatchMode`,
  password prompts, `ClearAllForwardings` and the URL's port and user still
  cannot be overridden.
- `dcap://`: a file still open when its context is freed no longer returns its
  control connection to the closed door's pool, where nothing would close it.
- `lfn:/grid/...` URLs are parsed as paths (they were split as if
  `lfn://grid/...`, host `rid`), so the core's `mkdir -p` climb and `parent()`
  stay inside the catalogue; `lfn:///grid/...` keeps working.
- `xgfalclient.testing.gridftp.GridFTPServer.url()` brackets an IPv6 host.
- `gsiftp://`/`ftp://` uploads and third-party copies, and the test GridFTP
  server, work on a CPython without `os.preadv` (one built for macOS before
  11, as conda's Intel macOS Python is): the local reader falls back to
  `os.pread` (`plugins.gridftp.data.positional_reader`) instead of failing
  every data transfer with `AttributeError`.
- `xgfalclient.testing.sftp.SSHServer`: a rekey it starts no longer reads the
  client's in-flight channel data as the client's `KEXINIT` (RFC 4253
  section 7.1 lets a client keep sending until it reads ours); that data is
  queued and its window credit sent after `NEWKEYS`. A malformed packet now
  ends the connection instead of leaving the client waiting for ever. CI's
  macOS `[krb5]` install check tests python-gssapi through
  `xgfalclient.crypto.krb5`, and that pykrb5 is absent, not `import krb5`.

### Packaging

- `publish.yml` gates the upload on PyPI, as xrdclient's does: it runs
  xrd-devtools' `chain_preflight.py pypi` on the wheel, so the exact
  `xrdclient==0.4.0` pin and the
  libraries must already be on PyPI as wheels, then installs the wheel with
  `--only-binary=:all:` from PyPI alone and runs `pip check` before the
  tag, changelog and gfal2-version checks.
- The chain's tooling is the new
  [xrd-devtools](https://github.com/rob-c/xrd-devtools) repository, used
  from a checkout (not on PyPI, so never a dependency):
  `tests/test_scorecard.py` is a few lines loading its scorecard plugin
  (found through pytest's `pythonpath`: `../xrd-devtools/src` or CI's
  `.dependencies/xrd-devtools/src`) instead of locating xrdclient's
  `tools/scorecard.py` through `XRDCLIENT_CHECKOUT`; it skips, saying so,
  without one, and is required in CI.
- CI calls xrd-devtools' reusable workflows (`static.yml`: ruff, mypy,
  complexipy, the scorecard and `xrddevtools conformance`; `tests.yml`;
  `chain.yml`: the duplicate and conformance gates over all seven
  repositories), and the remaining jobs take their candidates from
  xrd-devtools' one candidates action, which replaces
  `.github/actions/candidates`. `platforms.yml` calls xrd-devtools' platform
  workflow (moved there from xrdclient) with this commit, and
  `packaging/default.nix` applies xrd-devtools' Nix expression (`devtoolsSrc`
  and `xrdclientSrc` arguments). CI therefore needs `rob-c/xrd-devtools` to
  exist.

## [0.3.2] - 2026-10-07

### Fixed

- A doubled slash in a WebDAV request path (`/store//file`, a path-join
  artifact) is folded to one on the wire, so a strict server (CNAF's StoRM)
  does not answer `400` where EOS and dCache succeed. The fold is on the
  non-S3 path only - an S3 key's slashes are literal and signed - and an
  escaped `%2F` is left alone; the parsed URL is unchanged.
- A token-authorised third-party copy mints a short-lived macaroon at the far
  end for the delegated leg instead of forwarding a bare ambient token. An
  identity-mapped token (a DiracX token) is taken for a direct read or write,
  and to mint a macaroon, but refused on the server-to-server leg
  (`_far_token` used to short-circuit on the token, before the
  `RETRIEVE_BEARER_TOKEN` mint that is on by default); a token in the far
  URL's query is still left there, and a proxy copy is unchanged.

## [0.3.1] - 2026-10-06

### Changed

- Raised the declared Python floor from 3.9.2 to 3.10 and required
  `xrdclient==0.3.1`. On Python 3.9 botocore pins `urllib3<1.27`, which cannot
  be satisfied together with `urllib3>=2.2`, so a 3.9 install never resolved;
  the metadata now says so up front. Every supported platform package already
  uses a distribution-provided Python 3.10 or newer, so no deployment target
  changes. The code is still kept to 3.9 syntax.

## [0.3.0] - 2026-10-05

### Added

- Portable VOMS assertion inspection and verification across the existing
  X.509 stack: WebDAV/SRM mutual TLS, GridFTP/dCache GSI and XRootD. The original
  proxy chain is preserved; shared validation exposes VOs, ordered FQANs,
  generic attributes and per-assertion verdicts, with holder, validity, signer,
  signature, target, critical-extension, CA-chain and `vomsdir` LSC checks.
- RSA PKCS#1/PSS, P-256 ECDSA and Ed25519 VOMS signature support, plus automatic
  Intel/Apple Silicon Homebrew trust-directory discovery on macOS.
- Plain-language trust diagnostics retaining stable codes, exact paths and
  filesystem error numbers. Missing/corrupt/unreadable trust files, expired or
  not-yet-valid CA/signing certificates, permissions and missing/malformed/
  mismatched `.lsc` bindings each have a specific explanation and safe fix.
- Separate `check_vomses` preflight for missing files/folders, access failures,
  invalid UTF-8, malformed endpoint fields and invalid ports. An already-issued
  proxy remains usable without vomses configuration.
- JSON/XML output for all `gfal-*` commands, legacy commands, version commands,
  `python -m xgfalclient.cli` and `Gfal2Shell`. Help/version, usage/runtime
  errors, typed per-file results, staging handles/states, progress and bounded
  base64 binary stdout use xrdclient's versioned `storage-client-report` schema.
  Text output and numeric compatibility exit codes remain the default.
- Read-only native Kerberos cache diagnostics through pykrb5, retaining the
  cache name, principal, expiry and native error codes.

### Changed

- Updated the declared Python minimum from 3.9 to 3.9.2, retaining the Python
  3.9 minor-version floor. Clean-install readiness is documented below.
- Required `xrdclient==0.3.0` for the canonical shared core and XRootD transport.
  Base installs now include `root://` support; `xrootd` remains an empty
  installation compatibility extra. The dependency is one-way: xrdclient does
  not depend on or import xgfalclient.
- Replaced duplicate VOMS, DER, RSA, AES, Ed25519, P-256 and XML implementations
  with aliases/adapters to xrdclient. Existing import paths, exception identities
  and credential models are retained. Both certificate facades share
  cryptography-backed inspection and one bounded legacy fallback.
- Added `asn1crypto`, `botocore`, `cryptography`, `PyJWT[crypto]` and `urllib3`
  runtime dependencies for parsing, signing, cipher/curve operations, JWT
  diagnostics and connection/TLS setup. JWT inspection remains unverified
  diagnostics, never an authorization decision.
- Consolidated bounded HTTP requests and streamed copy/read-ahead orchestration
  in xrdclient, keeping GFAL credential, pool, spooled/known-length upload,
  progress/event, cleanup, durability, retry and numeric-error adapters.
- Removed GFAL's second XRootD bulk upload implementation. The shared engine
  handles framing, acknowledgements and settled WAIT-range replay while GFAL
  retains cancellation, progress and error policy.
- S3 replies, embedded errors, modeled fields and multipart manifests use
  botocore's shared codecs over GFAL's existing HTTP transport. GFAL addressing,
  credentials, metadata and transfer policy remain adapters.
- Removed custom OpenSSL/GSS ctypes bindings and local cipher/curve arithmetic.
  All SSH cipher backend selections use cryptography, including AES-GCM; old
  backend names remain compatibility selectors rather than separate engines.
- Native python-gssapi and pykrb5 live in the optional `krb5` extra. The old
  `ctypes` Kerberos selector aliases python-gssapi, so installations previously
  relying on implicit ctypes GSS now need `xgfalclient[krb5]`.
- XML declaration checks and bounded binary readers use the shared local
  standard-library implementation; no compiling XML parser or Construct
  dependency is required. gfal2/python3-gfal2 compatibility versions are unchanged.

### Fixed

- Partial writes complete before copy progress is reported; invalid write
  counts fail with the existing GFAL I/O error code rather than silently
  producing incomplete data.
- Failed S3 copy/completion replies, including HTTP 200 responses containing
  an error, cannot report success or trigger source deletion.
- User-facing errors remove internal scope prefixes and explain common failures
  in plain language. `GError.message`, `args`, numeric codes and exception
  classes retain their compatibility payloads; `str(error)` and
  `user_message` provide display wording.
- Damaged VOMS assertions, invalid UTF-8 and incomplete LSC subject/issuer pairs
  fail cleanly. Trust-directory access failures are not misreported as a missing
  LSC, and unrelated bad trust files do not invalidate an otherwise trusted VO.
- Generated documentation under `site/` is excluded from source distributions.

### Testing and packaging

- Added extensive VOMS/trust tests for malformed input, permissions, clock
  boundaries, signatures, holder/issuer/target policy, mixed-VO outcomes and
  actionable fixes, with independent OpenSSL checks when available.
- Added shared-module identity, credential compatibility, HTTP/transfer faults,
  acknowledgements/WAIT, cancellation, partial writes, user-error and all-command
  JSON/XML regression tests. Existing line/branch/condition coverage, API,
  performance, maintainability and real-service interop gates remain required.
- Added coordinated testing and packaging for AlmaLinux 8/9/10, CentOS Stream
  9/10, Ubuntu 24.04/26.04, Fedora 44 and Rawhide, NixOS 26.05 and Intel/Apple
  Silicon Homebrew, on x86-64 and ARM64, through xrdclient's canonical
  runner/workflow.
- Added private RPM/DEB packages requiring the exact paired Xrd version and
  package release, plus thin Nix recipes and Homebrew wheel bundles. Jobs check
  binary-only installs, installed JSON/XML commands and byte-identical copies,
  non-root hermetic suites, dependency inventories and install/removal.
- Corrected portable test expectations for filesystem-specific error numbers
  and isolated streamed-upload fault cases so delayed cleanup cannot mask the
  intended error scenario.

### Release readiness and limitations

- Publish xrdclient 0.3.0 before xgfalclient 0.3.0. Python 3.9.2 remains the
  declared floor, but its botocore/`urllib3>=2.2` resolution conflict is a release
  blocker. AlmaLinux 8/9 and Stream 9 jobs use Python 3.12; optional native
  Kerberos bindings may require Linux headers and a compiler.
- VOMS validates/transports existing assertions, not proxy acquisition. CA-path
  checks do not implement all RFC 5280 constraints or CRLs; pyhanko-certvalidator
  remains deferred to preserve Python 3.9 compatibility.
- The 0.3.0 candidates passed all nine RPM/DEB targets natively on ARM64,
  including Fedora Rawhide on Python 3.15, plus native-VM installs on
  AlmaLinux 9 and Ubuntu 24.04, the Nix package builds and a booted aarch64
  NixOS VM test, and Apple Silicon Homebrew installation, `brew test` and
  command checks. x86-64 artifacts come from the native hosted runners. See
  [the platform guide](docs/platforms.md) for the exact scope and optional
  skips.

## [0.2.0] - 2026-10-01

### Added

- Link-discovered Metalink v3/v4 replica failover for HTTP metadata, reads,
  positioned reads and downloads.
- Resumable HTTP downloads and retry-aware uploads, including parallel range
  transfers and bounded recovery when a connection repeatedly fails.
- Local-filesystem durability checks and recovery from transient stale handles,
  short I/O and cache writeback failures.
- Opt-in BRIX proxy and FUSE integration suites covering truncation,
  corruption, stalls, refused connections, partial `ENOSPC`, torn writes,
  replacement races and false `fsync` success.
- PEP 561 typing markers for `xgfalclient`, `gfal2` and `gfal2_util`.
- Strict documentation builds and an explicit security and release process.

### Changed

- Python 3.9 through 3.14 are tested in CI.
- Formatting, strict typing, selected security rules, condition coverage,
  cognitive-complexity regression checks and built-artifact inspection are
  release gates.
- The `xrootd` integration is validated alongside xrdclient 0.2, including its
  resilience and copy contracts.
- Package metadata and `xgfalclient.VERSION` now share one version source.

### Fixed

- A copy cannot report success before a regular local destination is durably
  flushed and its stable size agrees with the transferred byte count.
- HTTP recovery no longer silently restarts non-replayable work, accepts an
  ignored range as a positioned response or turns exhausted retries into a
  short successful copy.
- Failed copies consistently preserve the primary error and apply requested
  destination cleanup.

[0.4.0]: https://github.com/rob-c/xgfalclient/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/rob-c/xgfalclient/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/rob-c/xgfalclient/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/rob-c/xgfalclient/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rob-c/xgfalclient/compare/v0.1.0...v0.2.0
