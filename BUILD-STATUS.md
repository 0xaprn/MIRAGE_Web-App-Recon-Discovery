# Build and verification status — 0.5.0

Verification performed in the provided Linux build environment on Python 3.13.5.

- [x] `python3 -m compileall -q mirage launch_gui.py` — passed.
- [x] `python3 -m unittest discover -s tests -v` — 20 tests passed.
- [x] Loopback desktop API token gate and static UI serving tests — passed.
- [x] Desktop API end-to-end scan against an isolated local HTTP fixture — passed.
- [x] Interactive topology graph construction and multi-target relationship checks — passed.
- [x] `node --check mirage/webui/app.js` — passed.
- [x] Local HTTP fixture confirmed route, form, query parameter and JavaScript endpoint discovery.
- [x] Local HTTP fixture confirmed password form over HTTP detection without form submission.
- [x] Security assessment tests confirmed CSP unsafe-inline, cookie attribute, server version disclosure and short-HSTS observations.
- [x] NVD query construction test confirmed version-bearing technology banners are converted into exact product/version queries.
- [x] Local end-to-end engine scan against an isolated loopback HTTP fixture — passed.
- [x] Local redirect fixture confirmed off-scope redirect is blocked.
- [x] SQLite persistence and JSON/HTML report tests — passed.
- [x] CLI port parser tests — passed.
- [x] `pip wheel --no-deps --no-build-isolation` — passed; wheel built as `mirage_attack_surface-0.5.0-py3-none-any.whl`.
- [x] Local wheel installation into an isolated target directory and import/version check — passed.

Not performed:

- No live scan against an external production target.
- No independent validation of NVD API results or CVE applicability against a real deployed component inventory.
- No internet-scale discovery or performance benchmark.
- No independent security audit or penetration test of MIRAGE.
- No full Chromium browser visual automation or accessibility audit; CSS scaling and interaction code were inspected and JavaScript syntax was checked. A headless Chromium screenshot attempt timed out, so screenshot-perfect visual validation is not claimed.
- No target-side browser-rendered SPA, authenticated application or active exploit-verification tests.
- No signed Gentoo, Windows or macOS release packaging.

The topology is an interactive perspective rendering of relationships between assets actually observed by MIRAGE. It does not invent missing assets and does not imply complete target coverage. A CVE intelligence candidate is not a verified vulnerability; exact product identity, build, configuration and affected-version range must be confirmed independently.


## 0.5.0 additions
- Topology renderer polish: animated edge signals, luminous node halos, selection focus ring and refined spatial background.
- Existing 0.4.0 scan engines and operator controls retained; no new active exploitation capability added.
