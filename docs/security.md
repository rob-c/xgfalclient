# Security

The complete reporting policy, threat model, compatibility-sensitive limits
and deployment guidance are maintained in the repository's
[`SECURITY.md`](https://github.com/rob-c/xgfalclient/blob/main/SECURITY.md).

The operational defaults are:

- TLS peer verification on;
- changed SSH host keys rejected;
- SSH strict key exchange (the Terrapin, CVE-2023-48795, countermeasure) on
  the in-process `sftp://` transports: paramiko 3.4+ and the built-in one;
- HTTP content and sensitive logging off;
- bounded redirects, retries and response sizes;
- credentials scoped by URL-prefix boundaries;
- bearer-token files (every protocol) and, for `root://`, proxies and SSS
  keytabs read only when private (`0600`, owned by you; xrdsec's rule -
  see [Bearer-token files](#bearer-token-files)); and
- checksum and local durability failures reported rather than hidden.

Two explicit compatibility switches remove peer authentication:
`[<PLUGIN>] INSECURE=true` and SFTP `STRICT_HOST_KEY_CHECKING=no`. Keep both
out of production configuration. Also review the HTTP cross-host redirect
credential behaviour before trusting a redirecting endpoint.

## Bearer-token files

xgfalclient looks for a bearer token the way the WLCG Bearer Token Discovery
specification says, after anything set explicitly (`ctx.cred_set(...,
"BEARER")` for the URL, then `[BEARER] TOKEN`):

1. `$BEARER_TOKEN`;
2. the file `$BEARER_TOKEN_FILE` names;
3. `$XDG_RUNTIME_DIR/bt_u<uid>`;
4. `/tmp/bt_u<uid>` (`<uid>` is `id -u`).

That is the order xrdclient uses for `root://` - one search, xrdsec's
`credentials.find_bearer_token` - so the same shell logs in as
the same identity over `root://`, `davs://` and the rest. A step that finds
nothing - unset, no such file, only whitespace - passes to the next.

A token file is a secret, and `/tmp/bt_u<uid>` is a name anyone can predict
in a directory anyone can write. So every token file is read through
xrdsec's credential-file reader (`credentials.read_private_file`), the one
`root://` uses, and is used only when it is

- a regular file (not a directory, FIFO or device),
- owned by you (the effective uid; root included), and
- neither readable nor writable by group or others (`0600` or `0400`).

At the two predictable locations (3 and 4) a symbolic link is refused, not
followed; `$BEARER_TOKEN_FILE` was named by you and may be a link, but the
file it leads to is checked the same way. A file that fails a check is *not*
skipped in favour of the next location - that would log in as whoever left
a token there. The operation fails with `EACCES` (`Permission denied`) and a
message naming the file and the fix, for example:

```text
the bearer token file /tmp/bt_u1000 is readable by group or others
(mode 0644); run: chmod 600 /tmp/bt_u1000
```

`htgettoken`, `oidc-token` and `condor_vault_storer` already write `0600`.
If you create a token file by hand, `umask 077` first or `chmod 600` it.
