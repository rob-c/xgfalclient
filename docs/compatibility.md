# gfal2 compatibility

## Which import to use

Existing applications can use the package unchanged:

```python
import gfal2
ctx = gfal2.creat_context()
```

Code which may run beside the system bindings can be explicit:

```python
import xgfalclient as gfal2
```

`xgfalclient.install_as_gfal2()` is available for code which cannot have its
imports edited. Call it before any module imports the system `gfal2`; replacing
an already imported extension module would leave two incompatible type worlds
inside one process.

## Version meanings

The names intentionally answer different questions:

| Expression | Meaning |
| --- | --- |
| `xgfalclient.VERSION` / `xgfalclient.__version__` | this distribution's release |
| `gfal2.__version__` | compatible python3-gfal2 bindings release |
| `gfal2.get_version()` | compatible gfal2 C library release |
| `gfal-copy --version` | gfal2-util and gfal2 compatibility versions |

Do not use `gfal2.__version__` to detect xgfalclient features. Test the
operation you need or inspect `xgfalclient.VERSION` in code which imports the
project explicitly.

## What is held compatible

Public classes, functions, enums, call signatures, return shapes, `GError`
codes, plugin names, option groups, callback ordering, command options, output
and exit statuses are tested against gfal2 2.23.5, python3-gfal2 1.13.1 and
gfal2-util 1.9.1. Protocol behaviour is exercised against independent
in-process servers and real services in the opt-in interop suite.

Exact debug traces and internal C function-name prefixes are not an API.
Messages retain the useful operation and server text, but callers should
branch on `GError.code`.

## Deliberate safety differences

The project refuses a copy onto itself even with overwrite enabled, cleans a
failed destination when `transfer_cleanup` requests it, verifies third-party
copies by default, treats transfer timeout zero as unlimited, validates SFTP
host keys and does not replace a missing explicitly named X.509 proxy with a
different identity. These differences are also listed in the README and are
covered by regression tests.

## Validate an application migration

Run the application's own tests twice in fresh environments: once with the
system bindings and once with xgfalclient. Include cancellation, bulk calls,
callbacks and failure assertions—not only successful copies. Record any code
which compares full error strings or relies on undocumented object types.

For performance comparisons, warm both clients equally and use the paired
benchmark method described in [Performance](performance.md).
