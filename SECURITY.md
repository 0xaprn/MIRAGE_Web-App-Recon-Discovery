# Security Policy and Rules of Engagement

## Authorized use only

MIRAGE is a security-research and asset-discovery tool. Run it only against assets you own or have explicit written authorization to assess. Confirm the approved domains, IP ranges, ports, dates, request rates, test methods and emergency contact before starting.

## Operational behavior

The 0.5.0 release performs DNS RRset discovery, passive Certificate Transparency lookup, bounded HTTP(S) GET requests, read-only common exposure checks, and limited TCP connect checks, response-header and cookie posture checks, insecure password-form detection, and optional NVD CVE keyword enrichment for version-bearing technology banners. It does not submit forms, authenticate, guess credentials, deliver exploit payloads, upload files, alter server state, evade monitoring or establish persistence.

The operator must still consider third-party hosting, shared IPs, CDNs, redirects, DNS changes and third-party links. A domain relationship is not by itself proof that every resolved IP or linked service is within an engagement's authorization. Use narrow explicit targets and written rules of engagement.

## Reporting a vulnerability in MIRAGE

Do not publish sensitive details before maintainers have had a reasonable opportunity to investigate and address the issue. Include the affected version, reproducible steps, impact and a minimal proof of concept. Do not include real secrets or personal data in public reports.

## Data handling

Scan history is stored locally in SQLite. JSON and HTML exports may contain hostnames, URLs, response metadata and security observations. Protect reports as sensitive assessment data, restrict access and securely dispose of them according to the engagement's retention requirements.
