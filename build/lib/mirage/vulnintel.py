from __future__ import annotations

"""Read-only CVE intelligence enrichment using the public NVD CVE API.

Matches are deliberately emitted as candidates: a banner string is not sufficient
proof that a vulnerable component/version is installed or reachable.
"""
import json
import os
import re
import time
import urllib.parse
import urllib.request
from .models import Finding

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _component_queries(assets, limit=3):
    seen = set()
    patterns = [
        (re.compile(r"apache(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I), "Apache HTTP Server"),
        (re.compile(r"nginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I), "nginx"),
        (re.compile(r"php(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I), "PHP"),
        (re.compile(r"openresty(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I), "OpenResty"),
        (re.compile(r"microsoft-iis(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I), "Microsoft IIS"),
        (re.compile(r"tomcat(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.I), "Apache Tomcat"),
    ]
    for asset in assets:
        if asset.kind != "technology_hint":
            continue
        banner = asset.value
        for pattern, product in patterns:
            match = pattern.search(banner)
            if match:
                version = match.group(1)
                query = f"{product} {version}"
                if query.lower() not in seen:
                    seen.add(query.lower())
                    yield query, asset.details.get("url", banner)
                break
        if len(seen) >= limit:
            break


def query_nvd(query: str, timeout=8):
    params = urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 8})
    headers = {"User-Agent": "MIRAGE-Security-Research/0.4", "Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(f"{NVD_ENDPOINT}?{params}", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read(2_000_000))


def enrich_findings(assets, progress=None, timeout=8, max_queries=3):
    findings = []
    queries = list(_component_queries(assets, max_queries))
    for index, (query, affected) in enumerate(queries, 1):
        if progress:
            progress(f"Live vulnerability intelligence · NVD query {index}/{len(queries)} · {query}")
        try:
            data = query_nvd(query, timeout=timeout)
            for item in data.get("vulnerabilities", [])[:8]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), "No English description supplied by NVD.")
                metrics = cve.get("metrics", {})
                score = None
                severity = "info"
                for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    rows = metrics.get(metric_key, [])
                    if rows:
                        cvss = rows[0].get("cvssData", {})
                        score = cvss.get("baseScore")
                        severity = str(cvss.get("baseSeverity", "info")).lower()
                        break
                refs = [r.get("url") for r in cve.get("references", [])[:5] if r.get("url")]
                published = cve.get("published", "")
                findings.append(Finding(
                    title=f"NVD CVE candidate · {cve_id} · {query}",
                    severity=severity if severity in ("critical", "high", "medium", "low") else "info",
                    confidence="low", asset=affected,
                    description=(description[:1600] + "\n\nThis is a keyword-based intelligence match, not a verified vulnerable-version determination. Confirm exact product, build, configuration and affected-version range before treating it as applicable."),
                    evidence={"cve": cve_id, "nvd_query": query, "cvss_base_score": score, "published": published,
                              "source": "NIST National Vulnerability Database API", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "references": refs},
                    recommendation="Identify the exact deployed component build and compare it against the CVE's affected-version and configuration criteria. Patch or mitigate only after applicability is established.",
                    status="intel-candidate"))
        except Exception as exc:
            if progress:
                progress(f"NVD lookup unavailable for {query}: {exc}")
        if index < len(queries):
            time.sleep(6.2 if not os.environ.get("NVD_API_KEY") else 0.7)
    return findings
