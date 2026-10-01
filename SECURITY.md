# Security

## Reporting a vulnerability

Email <robert.andrew.currie@gmail.com> with a description and, if possible, a
small reproducer. Do not open a public issue for a problem which could expose
credentials or another user's data. Expect an acknowledgement within a few
working days.

## Threat model

The client acts with the caller's bearer tokens, X.509 proxies, Kerberos
tickets, object-store keys and SSH credentials. The network and remote server
may be faulty or hostile. The local account and Python process are trusted; an
attacker able to read their memory or credential files is outside this model.

The implementation is designed to prevent a failed or malicious peer from
turning malformed responses, redirects, partial transfers or retry ambiguity
into silent data corruption or unintended repeated mutations.

## Security properties

- TLS certificate and hostname verification are enabled by default. Only an
  explicit `[<PLUGIN>] INSECURE=true` setting disables verification.
- X.509 and GSI certificate chains are checked against the configured grid CA
  directory. Private keys are excluded from object representations.
- `Credential` redacts bearer tokens and passwords from `repr`; HTTP trace
  content is disabled by default. Applications must still treat debug logs as
  sensitive because URLs, remote diagnostics and explicitly enabled protocol
  logging may contain secrets.
- Credential lookup uses URL-prefix boundaries, so a token for `/alice` does
  not match `/alice-other`.
- SFTP host keys default to `accept-new`: first contact is recorded and a
  changed or revoked key is rejected. Passwords are never placed in an
  OpenSSH subprocess's arguments or environment.
- Redirects and retries are bounded. Uploads and namespace mutations are not
  replayed after an ambiguous response; retryable reads resume from a known
  byte boundary.
- Copy checksums and final local durability checks turn corruption, truncated
  output and delayed filesystem failures into errors rather than success.
- Protocol parsers bound declared lengths and map implementation exceptions to
  `GError`; callers do not receive raw sockets or TLS exceptions carrying
  internal state.

## Compatibility-sensitive limits

gfal2-compatible HTTP redirects forward an `Authorization` header to another
host when transport security is not reduced. They drop it for an HTTPS-to-HTTP
redirect to a different host, but a cross-host HTTPS redirect is treated as a
storage-element hand-off. Do not follow redirects from an endpoint you do not
trust with the same credential. Prefer URL-scoped credentials and HTTPS.

`[<PLUGIN>] INSECURE=true` and SFTP `STRICT_HOST_KEY_CHECKING=no` are explicit
escape hatches for test installations. They remove peer authentication and
must not be used in production.

Checksums detect accidental corruption; they do not authenticate a server
which supplies both bytes and checksum. Likewise, decoding token claims for
expiry is not signature verification—the storage service remains responsible
for validating a bearer token.

Some legacy protocols supported for compatibility do not provide modern
transport security in every deployment. Prefer `davs://`, `roots://`,
`gsiftp://` or verified `sftp://` and use least-privilege, short-lived
credentials.

The project implements protocol-required cryptographic encodings and SSH/GSI
operations in Python where the standard library has no interface. Those
modules are interoperability components, not a general-purpose cryptography
API. They are tested against published vectors and independent peers.

## Operational guidance

Keep token, proxy, key and configuration files readable only by the account
running the transfer. Avoid credentials in URL userinfo because URLs commonly
appear in logs and process diagnostics. Leave sensitive HTTP logging disabled,
set finite operation timeouts, and verify checksums for data which crosses a
trust boundary.
