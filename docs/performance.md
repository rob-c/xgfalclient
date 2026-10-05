# Performance against gfal2

Every number here compares xgfalclient with the real gfal2 2.23.5 Python
bindings (`python3-gfal2`, with davix 0.8.10, libXrdCl 5.9.7, Globus,
libdcap and libssh2 underneath), on the same machine, against the same
server, in the same run.

## How it was measured

* **Where.** Client and server containers on one Docker bridge network, on
  an x86_64 Mac's Docker VM. Nothing crossed Docker Desktop's port
  forwarding, which caps any client near 50 MiB/s and would measure the proxy
  rather than the client.
* **Servers.** AlmaLinux 9 packages: xrootd 5.9.7 serving `root://` and, via
  XrdHttp over TLS, `davs://`; globus-gridftp-server 13 with GSI; dCache
  11.2.7 for `dcap://`/`gsidcap://`; OpenSSH 9.9 for `sftp://`.
* **Client.** The AlmaLinux 9 system Python 3.9, which is what gfal2's
  bindings are built for. Both libraries authenticate with the same RFC 3820
  proxy from a throwaway test CA.
* **Method.** `benchmarks/bench_vs_gfal2.py`: every sample runs in a fresh
  interpreter, so neither library benefits from the other's imports or warm
  connections. Contenders alternate who runs first in each paired round;
  the median and full range are reported. `--gate` requires both the chosen
  median speedup and a one-sided sign-test result at the requested alpha.
  Data cases move a 512 MiB random file with `filecopy` (to or from a local
  file); metadata cases run 200 `stat`s, 200 `listdir`s of a 300-entry
  directory, or 200 ADLER32 `checksum`s in a loop.
* **Warm-up.** gfal2 loads every plugin inside `creat_context()`, before any
  timer starts; xgfalclient loads a plugin the first time a URL needs it.
  So each sample does one untimed `stat` first, and that first operation's
  latency is reported on its own row (`first op`) - the lazy loading is
  visible, not hidden.
* **Integrity.** Transfers were checked by sha256 when the harness was built;
  every performance change was checked the same way.

Absolute numbers depend on the host (this one was shared with other work);
the ratio within a run is what to read.

## Results

Higher is better, except `first op`.

### `davs://` (WebDAV over TLS, XrdHttp)

| case | gfal2 | xgfalclient | ratio |
| --- | --- | --- | --- |
| download | 481 MiB/s | **669 MiB/s** | 1.39× |
| upload | 56 MiB/s | **72 MiB/s** | 1.29× |
| stat | 15 ops/s | **84 ops/s** | 5.6× |
| listdir | 14 ops/s | **35 ops/s** | 2.4× |
| checksum | 17 ops/s | **1343 ops/s** | 80× |
| first op | 71 ms | 73 ms | level |

Metadata is faster because connections are pooled and reused: davix opens a
new TLS session for many of these calls. The upload ceiling is the server's.

### `root://` (xrootd, via xrdclient)

| case | gfal2 | xgfalclient | ratio |
| --- | --- | --- | --- |
| download | 425 MiB/s | **2177 MiB/s** | 5.1× |
| upload | 1080 MiB/s | **1501 MiB/s** | 1.39× |
| stat | 1442 ops/s | **2011 ops/s** | 1.39× |
| listdir | 282 ops/s | **371 ops/s** | 1.32× |
| checksum | 776 ops/s | **2389 ops/s** | 3.1× |
| first op | **6 ms** | 90 ms | 0.07× |

The one loss is the first operation: importing xrdclient takes about 90 ms,
which gfal2 pays for libXrdCl inside `creat_context`. It is paid once per
process.

### `gsiftp://` (GridFTP with GSI, globus-gridftp-server)

| case | gfal2 | xgfalclient | ratio |
| --- | --- | --- | --- |
| download | 1214 MiB/s | **1770 MiB/s** | 1.46× |
| upload | 1404 MiB/s | **1700 MiB/s** | 1.21× |
| stat | 926 ops/s | **1846 ops/s** | 2.0× |
| listdir | 207 ops/s | **380 ops/s** | 1.84× |
| checksum | 3.5 ops/s | 3.3 ops/s | level (server-bound) |
| first op | 92 ms | 124 ms | 0.74× |

A checksum is the server reading 512 MiB; both clients wait for it.

### `dcap://` and `gsidcap://` (dCache 11.2.7)

256 MiB, seven samples, measured with the plugin's own harness under the
same conditions.

| case | gfal2 | xgfalclient | ratio |
| --- | --- | --- | --- |
| dcap download | 913 MiB/s | **1057 MiB/s** | 1.16× |
| dcap upload | 556 MiB/s | **596 MiB/s** | 1.07× |
| gsidcap download | 610 MiB/s | **939 MiB/s** | 1.54× |
| gsidcap upload | 361 MiB/s | **484 MiB/s** | 1.34× |
| gsidcap stat | 45.7 ms | **3.3 ms** | 14× |
| dcap first stat | **8.8 ms** | 14.9 ms | 0.59× |

### `sftp://` (OpenSSH 9.9)

256 MiB of random data, best of three, sha256-verified in both directions.

| case | gfal2 (libssh2) | xgfalclient |
| --- | --- | --- |
| download, key (OpenSSH tier) | 232-249 MB/s | **292-317 MB/s** |
| upload, key (OpenSSH tier) | see below | **245-312 MB/s** |
| download, password (in-process SSH-2) | 249 MB/s | **296 MB/s** |
| upload, password (in-process SSH-2) | see below | **199 MB/s** |

**gfal2's sftp upload loses data.** Uploading the 256 MiB file through
gfal2's sftp plugin reported success in 0.08 s and left 6 MB on the
server; the same upload through xgfalclient leaves all 268,435,456 bytes,
byte-identical. There is no gfal2 upload number to compare against.

Passwords are only ever used inside the process - never handed to an `ssh`
subprocess - so a password login takes the in-process SSH-2 transport. It
now negotiates aes128-gcm@openssh.com through `cryptography`; the local
OpenSSL ctypes and pure-Python fallback backends have been removed. The
measurements below predate that rebase and need to be rerun for the new backend. Upload there is
bounded by the server's fsync and its fixed 2 MiB channel window.

## Where the speed comes from

* **Pipelining.** Several requests in flight per connection everywhere the
  protocol allows it: xrootd reads and writes, dcap read-ahead, SFTP reads
  and writes, GridFTP MODE E streams.
* **No copies.** Replies land in their destination buffers (`recv_into`,
  `readinto` on the `ssl` object itself); writes go out as header plus the
  caller's buffer.
* **Parallel streams** where the server allows them: HTTP ranged GETs,
  xrootd bulk reads across connections, GridFTP MODE E.
* **Connection reuse** for metadata, and no redundant round trips (no stat
  before every listing, no new TLS session per call).
* **Large writes over TLS.** `socket.sendfile` silently falls back to 8 KiB
  sends on a TLS socket; uploads write 4 MiB at a time instead.

## Reproducing

```console
$ python benchmarks/bench_vs_gfal2.py --base davs://server:8443/data/bench \
      --size 512 --repeat 5 --json results.json
$ python benchmarks/bench_vs_gfal2.py --base davs://server:8443/data/bench \
      --size 512 --repeat 9 --gate --min-ratio 1.10
```

`--base` is a writable directory URL; the harness creates its fixtures there.
Run it in a container on the same network as the server, with both gfal2's
bindings and xgfalclient importable. The gate deliberately rejects
xgfalclient's `gfal2` compatibility shim as the reference implementation.
Checksum is report-only by default because it is normally bounded by the
server reading the file, not by either client.
