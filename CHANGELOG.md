# Changelog

Notable user-visible changes are recorded here. The `xgfalclient` version is
independent of the gfal2 and python3-gfal2 compatibility versions reported by
the replacement API.

## [0.3.1] - Unreleased

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

[0.3.1]: https://github.com/rob-c/xgfalclient/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/rob-c/xgfalclient/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rob-c/xgfalclient/compare/v0.1.0...v0.2.0
