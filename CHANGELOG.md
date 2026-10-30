# Changelog

## 0.5.0 — consolidated release
- Refined the 3D topology renderer with animated edge signals, luminous node halos, selected-node focus rings, deeper spatial grid treatment and improved contrast.
- Retained the 0.4.0 larger typography, clickable metric drill-down, asset/finding inspectors, scan profiles and bounded scan controls.
- Kept the assessment model non-destructive: discovery and observable configuration checks only; no exploit execution or payload delivery.
- Documentation and package metadata aligned to 0.5.0.


## 0.4.0 — 2026-10-30

### Added
- Increased desktop UI scale and typography for ordinary desktop readability with responsive adjustments.
- Clickable mission-control metric cards, asset inventory rows and finding rows with structured detail inspectors.
- Assessment profiles: balanced, deep web mapping, infrastructure focus and fast snapshot, plus custom scan tuning.
- Optional live NVD CVE intelligence for version-bearing Apache, nginx, PHP, OpenResty, IIS and Tomcat banners.
- Expanded security assessment for CSP unsafe directives, short HSTS max-age, missing response-policy headers, cookie attributes, disclosed server versions, X-Powered-By and password forms served over HTTP.
- Regression tests for security observations, password-form detection and NVD query construction.

### Changed
- NVD matches are explicitly low-confidence intelligence candidates; lookup failures are activity events, not false vulnerability findings.
- Release version bumped to 0.4.0.

### Verification
- 20 automated tests pass, including local HTTP integration tests and scope redirect checks.
- Full Chromium screenshot verification remains outstanding and is documented in BUILD-STATUS.md.

## 0.3.0 — 2026-10-30

### Added
- Replaced the prototype desktop widget interface with a self-contained local desktop web console.
- Added a WebGL-rendered 3D topology with perspective depth, rotation, zoom, node selection and evidence inspector.
- Added live status polling, operation telemetry, metric cards, filtering, batch target import and browser-based report downloads.
- Added a loopback-only HTTP server with a random per-launch token required for API access.
- Bundled all UI assets locally; no CDN or remote visualization service is used.

### Changed
- `mirage-gui` and `launch_gui.py` now launch the WebGL desktop console.
- Removed the unused Tk prototype and its runtime requirement.
- Version bumped to 0.3.0.

### Verification note
- The local API, token gate, static assets, engine integration and JavaScript syntax are tested. Full Chromium visual automation is not claimed in the build environment.

## 0.2.0 — 2026-10-30

### Added
- Redesigned desktop mission-control interface with navigation, metric cards, scan telemetry, elapsed time and live activity feed.
- Interactive perspective 3D-style asset topology with rotate, zoom and click-to-inspect behavior.
- Multi-target list import and aggregate reporting in the GUI.
- DNS RRset enrichment for CNAME, MX, NS, TXT, SOA, CAA and SRV using dnspython.
- Common read-only exposure-path checks and wildcard-CORS observations.
- HTTP probing on discovered common non-standard web ports.
- Asset inventory and finding views with structured metadata.

### Changed
- Removed the GUI authorization acknowledgement checkbox; technical scope checks remain enforced by the discovery engine.
- Removed the CLI acknowledgement flag requirement; operators remain responsible for permission and engagement scope.
- Improved visual hierarchy, scan-state visibility, topology visualization and export controls.
- Version bumped to 0.2.0.

### Limitations
- Browser-rendered SPA crawling, authenticated mapping, full API schema analysis and active exploit verification remain future work.
- The topology is a perspective graph of observed relationships, not a geospatial map or proof of complete asset coverage.
