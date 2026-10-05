# JSON and XML output

Every shipped command accepts `--output-format json|xml|text`, `--json` and
`--xml`: all `gfal-*` commands, legacy aliases, `gfal2_version`,
`gfal_srm_ifce_version`, `python -m xgfalclient.cli` and `Gfal2Shell`.
Human-readable text remains the default, with existing numeric exit codes.

```console
$ gfal-ls --json davs://storage.example/store/project
$ gfal-copy --output-format xml input.root davs://storage.example/store/input.root
$ gfal-bringonline --json --from-file urls.txt
$ gfal-stat --xml --help
$ gfal2_version --json
```

Machine mode emits one versioned document on stdout and leaves stderr empty.
It includes typed metadata/results, per-file acknowledgements, staging request
identifiers and states, available progress/events, numeric errors, diagnostics,
help and versions. Binary stdout from `cat` or `copy … -` becomes base64
content records. Copied destination files and explicit diagnostic log files
retain their existing formats.

The shared schema is `storage-client-report`, version `1`. JSON has `tool`,
`command`, ordered `records` and a `summary` with `exit_code`, `ok`,
`error_count` and `record_count`. XML represents the same typed values.
Read the [shared report contract](https://rob-c.github.io/xrdclient/output/)
for record kinds, XML decoding rules, binary offsets and compatibility details.
The canonical implementation lives in the required xrdclient dependency;
xrdclient does not depend on or import this client.

Important integration rules:

- Check `summary.ok`, not only the process exit status: compatibility staging
  and some batch commands can exit 0 while individual files fail. Queued is
  not ready, and progress is not proof of final durability.
- Keep staging identifiers opaque and preserve per-file identities. Error
  codes keep their original namespace; OS `errno` is a separate nullable field.
- Do not parse `message` records to recover results. Results/error fields are
  built from library values. The `gfal-token` result intentionally contains
  the requested token; protect stored reports as you would ordinary token output.
- Reports are delivered on completion, not as a live progress stream. Records
  spill to temporary disk after 1 MiB; binary chunks are bounded to 1 MiB
  before base64 encoding. Large reports need temporary disk space.
- Completed batch records survive a later failure. Reconcile destinations
  before retrying a recursive transfer with incomplete child acknowledgements.

External Rucio/FTS adapters can consume these generic reports while retaining
their own service dependencies, job IDs and scheduling. Neither client imports
or manages those services. Concurrent CLI calls in one interpreter are not
supported; use subprocesses or the normal Python APIs.
