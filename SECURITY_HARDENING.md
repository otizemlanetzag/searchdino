# SearchDino Security Hardening

This project uses defense in depth. Security does not depend on hiding implementation details.

## Transport encryption

Production deployments MUST terminate traffic with TLS (HTTPS) at a trusted reverse proxy or load balancer. The application adds HSTS when the WSGI request scheme is HTTPS.

Use a current TLS configuration, disable obsolete TLS versions/ciphers, and redirect HTTP to HTTPS at the edge.

## Application-layer protections

The WSGI boundary now provides:

- Content Security Policy (CSP)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- strict `Referrer-Policy`
- restrictive `Permissions-Policy`
- Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy
- HSTS on HTTPS requests
- rejection of TRACE requests
- query-string size limits
- request-body size limits
- invalid `Content-Length` rejection

## Secrets

Never commit production secrets. `SEARXNG_SECRET` must be supplied through the deployment environment/secret manager. Rotate it if exposure is suspected.

Do not put passwords, API keys, private keys, cookies, or tokens in source code, configuration committed to Git, logs, or issue reports.

## Encryption at rest

The application should not invent a custom encryption scheme. If persistent sensitive data is introduced, use authenticated encryption from a maintained cryptographic library (for example AES-GCM or ChaCha20-Poly1305) with keys stored outside the repository. Passwords must be hashed with a password-specific KDF rather than encrypted.

## Network isolation

The application binds to `127.0.0.1` by default. If exposed publicly, put it behind a hardened TLS reverse proxy/firewall and keep internal services such as Valkey inaccessible from the public network.

## Important limitation

No software can honestly guarantee that it is "unhackable". These controls reduce attack surface and limit the impact of common classes of attacks; regular dependency updates, logging/monitoring, backups, and independent security review are still required.
