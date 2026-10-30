# Threat model

## Assets to protect
- The operator's machine and local scan database.
- Credentials and sensitive information that may appear in URLs, headers or reports.
- Third-party systems that must not be contacted outside the engagement scope.
- Integrity of discovery data and the trustworthiness of reported findings.

## Trust boundaries
- Target-provided HTTP responses, redirects, HTML, JavaScript, DNS answers and CT records are untrusted.
- The operator-supplied target is the initial technical scope boundary; it does not establish permission.
- The local database and exported reports may contain sensitive reconnaissance information.

## Controls in 0.5.0
- Scope checks before requests and on redirect destinations.
- Explicit technical scope boundaries for domains, URLs, IP addresses and CIDR ranges. The operator remains responsible for permission and rules of engagement.
- Bounded worker count, timeouts, page count, crawl depth and response sampling.
- No form submission, authentication attempts, exploit payloads, file uploads, persistence or stealth features.
- HTML report values are escaped.
- Scan history is local; no telemetry service is implemented.
- Desktop HTTP service binds to loopback only; API calls require a random per-launch token.
- Static UI assets are bundled locally; no third-party CDN scripts or fonts are loaded.
- Responses include a restrictive Content Security Policy and no-store cache policy.

## Known residual risks
- DNS can change between resolution and connection; this preview does not pin resolved addresses or defend against DNS rebinding.
- System proxy configuration can affect routing.
- The domain scope model includes subdomains, which may be operated by third parties; operators must validate ownership and written authorization.
- The HTTP client does not implement a full browser security model or authenticated-session isolation.
- Reports can expose sensitive URL parameters and infrastructure details; protect them accordingly.

## Planned controls
- Optional explicit private-address policy and DNS pinning.
- Per-scan request/host/port budgets and cancellation.
- Secret/PII redaction in reports and evidence storage.
- Encrypted credential vault before authenticated scanning is introduced.
- Signed scan manifests and tamper-evident event logs.
