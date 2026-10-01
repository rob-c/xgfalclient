# Changelog

Notable user-visible changes are recorded here. The `xgfalclient` version is
independent of the gfal2 and python3-gfal2 compatibility versions reported by
the replacement API.

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

[0.2.0]: https://github.com/rob-c/xgfalclient/compare/v0.1.0...v0.2.0
