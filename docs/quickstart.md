# Quickstart

All commands support [JSON/XML output](output.md), including errors and
help/version: append `--json`, `--xml` or `--output-format json|xml`.

## Install safely

The distribution provides top-level `gfal2` and `gfal2_util` packages. Use a
virtual environment so they do not accidentally shadow an operating-system
installation.

```console
$ python3 -m venv .venv
$ .venv/bin/python -m pip install xgfalclient          # includes root://
$ .venv/bin/python -m pip install 'xgfalclient[krb5]'    # optional native Kerberos
```

## Create and close a context

`Gfal2Context` owns plugin connections and credentials. Prefer a context
manager when the context does not live for the whole process.

```python
import gfal2

with gfal2.creat_context() as ctx:
    for name in ctx.listdir("davs://storage.example/store/project"):
        print(name)
```

The familiar operations are present: `stat`, `lstat`, `open`, `listdir`,
`mkdir`, `mkdir_rec`, `rename`, `unlink`, `checksum`, extended attributes,
tape staging, QoS and token retrieval.

## Read and write

The compatibility file object keeps gfal2's text-returning `read` method and
adds byte-preserving methods for new code.

```python
with gfal2.creat_context() as ctx:
    remote = ctx.open("davs://storage.example/store/input.bin", "r")
    try:
        data = remote.read_bytes(1024)
    finally:
        remote.close()
```

Open modes are `r`, `w` and `rw`. Use `pread_bytes(offset, count)` when
several consumers need independent positions.

## Copy with explicit policy

```python
import gfal2

with gfal2.creat_context() as ctx:
    params = ctx.transfer_parameters()
    params.overwrite = False
    params.create_parent = True
    params.set_checksum(gfal2.checksum_mode.both, "ADLER32", "")
    ctx.filecopy(
        params,
        "davs://source.example/store/a.root",
        "file:///srv/data/a.root",
    )
```

The default refuses to overwrite, cleans a partial destination after failure
and applies a finite transfer timeout. A local destination is flushed and its
stable size is checked before success is returned.

## Handle errors by code

`GError.code` is an `errno` value and `GError.message` is the gfal2-style
diagnostic. Branch on the code, not message text.

```python
import errno
import gfal2

try:
    gfal2.creat_context().stat("davs://storage.example/store/missing")
except gfal2.GError as error:
    if error.code == errno.ENOENT:
        print("not found")
    else:
        raise
```

## Configure without global state

Options are per context and use the same group/key names as gfal2:

```python
ctx = gfal2.creat_context()
ctx.set_opt_integer("CORE", "CONN_RETRY", 4)
ctx.set_opt_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 120)
ctx.set_opt_boolean("HTTP PLUGIN", "METALINK", True)
```

`GFAL_CONFIG_DIR`, existing `/etc/gfal2.d/*.conf` files and standard WLCG
credential environment variables are discovered automatically. Explicit
context options and URL-scoped credentials are easier to audit in services.
