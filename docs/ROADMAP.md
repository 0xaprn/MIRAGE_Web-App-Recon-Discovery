# MIRAGE roadmap

Roadmap status is evidence-based. A feature is not considered implemented until its code, tests and documentation are present.

## 0.2.0 — visual and discovery upgrade
- [x] Mission-control desktop GUI with live run state, elapsed timer and activity feed
- [x] Interactive perspective topology with rotation, zoom and node inspection
- [x] Asset, findings and activity workspaces
- [x] Multi-target import and aggregate results
- [x] DNS RRset enrichment through dnspython
- [x] Non-standard common web-port probing
- [x] Read-only common exposure checks and wildcard-CORS observation
- [x] Remove GUI authorization checkbox; retain technical scope enforcement

## 0.3.0 — WebGL desktop console
- [x] Local-only desktop web shell with per-launch random API token
- [x] WebGL-rendered interactive 3D asset topology
- [x] Live state polling, scan telemetry, event feed and export controls
- [x] Desktop browser app-mode launch and default-browser fallback
- [x] Multi-target aggregate results and graph inspector

## 0.4 — deeper infrastructure intelligence
- [ ] ASN/RDAP and hosting-provider enrichment
- [ ] Historical DNS and certificate relationship analysis
- [ ] CDN, reverse-proxy and origin relationship classification
- [ ] Better IPv6 range planning and bounded large-range execution
- [ ] Virtual-host candidate analysis with explicit operator-supplied candidates
- [ ] DNS resolver retry, caching, DNSSEC and per-record evidence
- [ ] Scan cancellation, pause/resume and durable event stream

## 0.5 — modern application mapping
- [ ] Browser-rendered SPA crawling and route discovery
- [ ] Authenticated profiles with encrypted-at-rest session storage
- [ ] JavaScript AST and source-map analysis
- [ ] OpenAPI/Swagger ingestion and GraphQL schema mapping
- [ ] Parameter provenance and endpoint relationship graph improvements
- [ ] Historical snapshots and attack-surface change detection

## 0.6 — security research workbench
- [ ] Reproducible safe test plans and request/response evidence bundles
- [ ] Authentication and access-control comparison workflows
- [ ] Non-destructive injection and input-validation verification
- [ ] File-handling and API authorization research workflows
- [ ] Finding deduplication, confidence calibration and remediation context
- [ ] Redaction controls for secrets and personal data in evidence exports

## 1.0 — release criteria
- [ ] Independent security review and threat-model update
- [ ] Broad local-fixture and regression coverage, including GUI workflows
- [ ] Measured performance and memory benchmarks on documented datasets
- [ ] Signed/reproducible Linux packaging and tested Windows/macOS packaging
- [ ] Accessibility and usability review
- [ ] Stable plugin/engine API and migration policy
- [ ] Complete operator, developer and extension documentation

No release should claim total target coverage or guaranteed vulnerability discovery.


## 0.4.0 — assessment and operator workflow

- Improved desktop legibility and object-level inspectors for assets and findings.
- Added scan profiles and optional live NVD keyword intelligence.
- Expanded passive/read-only security posture checks for headers, cookies and password forms over HTTP.
- Remaining major work: authenticated/browser-rendered mapping, precise CPE and affected-version matching, comprehensive asset-provider integrations, and a broad passive/active-but-non-destructive vulnerability check library.
