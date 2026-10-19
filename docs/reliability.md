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

## Cancellation

`Gfal2Context.cancel()` stops what is in flight without waiting for the next
chunk. HTTP, XRootD, GridFTP, dCap and SFTP register the sockets an operation
is blocked on (for SFTP over the system `ssh`, the `ssh` process is ended); `cancel()` shuts them down, so a `recv` on a server that has gone
silent wakes at once and the operation fails with `ECANCELED` (a copy with
gfal2's "Transfer canceled") instead of holding the caller for the whole
operation timeout. Retries and reconnects of a cancelled operation are refused
while the cancel drains; removing a cancelled copy's partial destination is not.
`cancel()` itself waits at most `[CORE] CANCEL_TIMEOUT` seconds (default 10;
`0` waits without limit, as gfal2 does) for operations blocked where nothing
can wake them, such as a TCP connect or an SSH handshake. Third-party plugins
can use the same hook: `Gfal2Context.abort_on_cancel(sock)` (or
`register_abort`/`unregister_abort`, or `Transfer.abort_on_cancel` in a copy).
XRootD's multi-connection bulk download is still only cancelled between chunks:
xrdclient does not expose its connections.

## Local filesystem failures

Read-only local operations retry transient `EAGAIN`, `EBUSY`, `EINTR`,
`ESTALE` and `ETIMEDOUT`. A reopened source must still have the same device,
inode, size and nanosecond timestamps. If it was replaced, the copy fails with
`ESTALE` instead of combining generations.

Only a reader which encounters a fault reduces its request size, so the normal
4 MiB streaming path stays fast. On Linux, a copy between two regular local
files moves its bytes with `copy_file_range(2)`, `COPY_BUFFERSIZE` at a time
(with the same progress, cancellation and final-sync checks), and hands over
to the read/write pipeline at the offset reached when the kernel refuses
(`EXDEV`, `ENOSYS`, `EOPNOTSUPP`, `EINVAL`, `ETXTBSY`), stops short of the
source's size, or reports one of the transient read errors above (after the
same reopen-and-verify recovery). Short and zero-progress I/O are handled
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
