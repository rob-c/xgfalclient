# Security

The complete reporting policy, threat model, compatibility-sensitive limits
and deployment guidance are maintained in the repository's
[`SECURITY.md`](https://github.com/rob-c/xgfalclient/blob/main/SECURITY.md).

The operational defaults are:

- TLS peer verification on;
- changed SSH host keys rejected;
- HTTP content and sensitive logging off;
- bounded redirects, retries and response sizes;
- credentials scoped by URL-prefix boundaries; and
- checksum and local durability failures reported rather than hidden.

Two explicit compatibility switches remove peer authentication:
`[<PLUGIN>] INSECURE=true` and SFTP `STRICT_HOST_KEY_CHECKING=no`. Keep both
out of production configuration. Also review the HTTP cross-host redirect
credential behaviour before trusting a redirecting endpoint.
