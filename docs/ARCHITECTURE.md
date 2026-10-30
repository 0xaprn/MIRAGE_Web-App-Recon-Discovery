# Architecture

MIRAGE 0.5.0 is a Python desktop application with a small runtime footprint and optional enrichment through dnspython.

```text
CLI / loopback desktop web console
        |
      Engine
        |
  Scope allow-list  <---- every active URL/host is checked before use
        |
    Discovery
     |   |   |
     |   |   +-- bounded HTTP crawl, HTML extraction, JS heuristics, exposure checks
     |   +------ TCP connect-only service checks and common web-port probing
     +---------- DNS RRsets + Certificate Transparency + wordlist resolution
        |
  Asset / Finding models
        |
  SQLite history + JSON / HTML report exporters
```

## Boundaries

- `scope.py` parses the target and enforces hostname/IP membership.
- `discovery.py` contains collection methods and records provenance.
- `engine.py` coordinates a scan and assembles a stable result.
- `models.py` defines the serializable asset and finding records.
- `store.py` persists scan snapshots in SQLite.
- `report.py` exports the same result object to JSON and standalone HTML.
- `cli.py` and `desktop.py` are presentation/interaction layers; neither implements discovery itself. `desktop.py` serves the bundled WebGL interface from a loopback-only HTTP server.

## Concurrency and resource controls

HTTP crawl work uses a bounded thread pool. Worker count is capped at 32. Page count, depth, request timeout and inter-request delay are configurable. Response bodies are sampled with explicit size limits. TCP connection checks use a bounded worker pool and a short connect timeout.

## Trust model

All discovered names, URLs, headers, response bodies and CT entries are untrusted input. They are treated as observations, never as instructions. Redirect destinations and extracted URLs must pass the scope check before MIRAGE follows them. Report output is HTML-escaped.

## Known limitations

The crawler does not execute target-side JavaScript or preserve authenticated browser sessions. DNS RRset enrichment covers common types through dnspython but does not provide historical DNS or full DNSSEC analysis. TCP discovery is connect-only and bounded; there is no UDP scanner or deep protocol fingerprint database. The desktop topology is a local WebGL perspective rendering of observed asset relationships, not a geospatial map or graph database. There is no exploit engine or active injection testing.
