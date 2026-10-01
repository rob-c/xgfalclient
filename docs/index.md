# xgfalclient

`xgfalclient` is a pure-Python replacement for the `gfal2` Python bindings and
gfal2-util commands. It keeps the API, plugin model, error codes and command
line that FTS, Rucio and DIRAC integrations expect, without a compiled gfal2,
Davix, XrdCl, Globus or SRM stack.

```python
import gfal2

with gfal2.creat_context() as context:
    info = context.stat("davs://storage.example/store/data.root")
    print(info.st_size)
```

Use the project as `import gfal2` for compatibility or
`import xgfalclient as gfal2` when coexistence with the system bindings needs
to be explicit. The package version is `xgfalclient.VERSION`; the compatibility
module deliberately reports the versions of the bindings and library it
replaces.

## Start here

- [Quickstart](quickstart.md) covers contexts, files, copies, errors and
  configuration.
- [Compatibility](compatibility.md) explains import choices and deliberate
  differences from the C-backed client.
- [Reliability](reliability.md) documents retry, integrity and local
  durability guarantees.
- [Performance](performance.md) gives reproducible comparisons with gfal2.
- [Security](security.md) describes trust boundaries and operational risks.
- [Developing](DEVELOPING.md) contains the contributor contracts and quality
  gates.
