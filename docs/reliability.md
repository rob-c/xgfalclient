# Reliability and recovery

Retries are useful only when they preserve meaning. xgfalclient distinguishes
operations which can safely be repeated from mutations whose outcome is
unknown after the connection disappears.

## Network failures

HTTP `GET`, `HEAD`, `OPTIONS` and `PROPFIND` retry transport failures up to
`[CORE] CONN_RETRY`. Reads resume from the last delivered byte and require a
valid range response; a proxy which strips `Range` cannot silently splice the
whole object into the middle of a file. Exhausted retries remain errors.

Backoff defaults to 50 ms and doubles to a one-second cap when
`CONN_RETRY_INTERVAL` is absent. Setting the interval explicitly uses that
fixed value, including zero for tests or fail-fast deployments. Operation
timeouts still bound each attempt.

Uploads are retried only when their body can be replayed and the request is
known not to have completed. Namespace mutations are not blindly repeated
after an ambiguous disconnect.

Enable `[HTTP PLUGIN] METALINK=true` to discover and cache a server-advertised
Metalink only after the original endpoint fails. Replica checksums are used to
reject corrupt complete bodies; failover remains bounded by the configured
retry policy.

## Local filesystem failures

Read-only local operations retry transient `EAGAIN`, `EBUSY`, `EINTR`,
`ESTALE` and `ETIMEDOUT`. A reopened source must still have the same device,
inode, size and nanosecond timestamps. If it was replaced, the copy fails with
`ESTALE` instead of combining generations.

Only a reader which encounters a fault reduces its request size, so the normal
4 MiB streaming path stays fast. Short and zero-progress I/O are handled
explicitly and bounded.

A completed copy to a regular local file performs a final flush, closes the
handle and checks the stable size before returning. This exposes delayed
`ENOSPC`/`EIO`, FUSE writeback failure and acknowledged-but-unpublished writes.
Special sinks such as pipes and `/dev/null` do not pretend to offer regular
file durability.

## Integrity and cleanup

Use source and destination checksums for data crossing an unreliable path.
`TransferParameters.transfer_cleanup` is enabled by default; a failed copy
removes the partial destination without replacing the primary error with a
cleanup error. Third-party transfers are verified after completion unless
`[CORE] VERIFY_THIRD_PARTY=false` is set.

Retries do not turn checksum failure into another attempt against the same
corrupt complete body. Integrity failure is evidence, not a transient socket
event.

## Fault-injection evidence

The normal suite contains deterministic protocol faults. The opt-in BRIX
suites add a real TCP fault proxy and a FUSE cache which can truncate, stall,
corrupt, return partial I/O, replace files and lie about writeback. Commands
and the covered scenarios are in [Developing](DEVELOPING.md).
