from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from urllib.parse import urlsplit

KIND_COLORS = {
    "domain": "#48e5f2", "subdomain": "#568bff", "ip": "#a78bfa", "tcp_service": "#f6b85f",
    "http_service": "#50e3a4", "url": "#d5e6ff", "route": "#f472b6",
    "parameter": "#f6b85f", "form": "#ff8d72", "javascript": "#b69cff",
    "api_candidate": "#ffcc66", "tls_certificate": "#50e3a4",
    "technology_hint": "#8ba9c9", "robots": "#8195b2", "sitemap": "#8195b2",
    "robots_path": "#f472b6",
}


def build_topology(assets, target=""):
    """Build a graph only from observed assets and their recorded provenance."""
    if not assets: return [], []
    records = list(assets)
    by_key = {(a.kind, a.value): i for i, a in enumerate(records)}
    domain_indices = [i for i,a in enumerate(records) if a.kind == "domain"]
    ip_indices = [i for i,a in enumerate(records) if a.kind == "ip"]
    root_candidates = domain_indices or [i for i in ip_indices if records[i].source in ("explicit-ip-target","cidr-expansion")]
    if not root_candidates and ip_indices: root_candidates = ip_indices[:1]

    def root_domain_parent(host):
        if not host: return None
        host=host.strip("[]").lower()
        matches=[(len(records[i].value),i) for i in domain_indices if host == records[i].value or host.endswith("."+records[i].value)]
        return max(matches)[1] if matches else None

    def host_parent(host):
        if not host: return None
        host = host.strip("[]").lower()
        direct = by_key.get(("subdomain",host))
        if direct is not None: return direct
        direct = by_key.get(("domain",host))
        if direct is not None: return direct
        try:
            ipaddress.ip_address(host)
            return by_key.get(("ip",host))
        except ValueError:
            return root_domain_parent(host)

    layer = {"domain":0,"subdomain":1,"ip":1,"tcp_service":2,"http_service":2,"tls_certificate":2,"dns_record":2,"url":3,"route":4,"form":4,"javascript":4,"api_candidate":4,"parameter":5,"technology_hint":3,"robots":3,"sitemap":3,"robots_path":4,"exposed_resource":4}
    groups = defaultdict(list)
    for i,a in enumerate(records): groups[layer.get(a.kind,3)].append(i)
    positions = {}
    for depth, indices in groups.items():
        count = len(indices)
        if depth == 0:
            radius = .38 if count > 1 else 0.0
            for j,i in enumerate(indices):
                angle = 2*math.pi*j/max(1,count)
                positions[i] = (math.cos(angle)*radius, math.sin(angle)*radius*.60, math.sin(angle)*.22)
            continue
        radius = .55 + depth * .42
        for j,i in enumerate(indices):
            angle = (2*math.pi*j/max(1,count)) + depth*.41
            wobble = math.sin(j*1.71+depth)*.26
            positions[i] = (math.cos(angle)*radius, math.sin(angle)*radius*.60, math.sin(angle*2+depth)*.48+wobble*.45)

    edges = set(); roots = set(root_candidates)
    for i,a in enumerate(records):
        if i in roots: continue
        parent = None; d = a.details or {}
        if a.kind == "subdomain":
            parent = root_domain_parent(a.value)
        elif a.kind == "ip":
            parent = host_parent(d.get("hostname"))
        elif a.kind in ("http_service","tcp_service","tls_certificate"):
            host = urlsplit(a.value if "://" in a.value else "//"+a.value).hostname
            parent = host_parent(host)
        elif a.kind == "url":
            p = urlsplit(a.value); service = f"{p.scheme}://{p.netloc}"
            parent = by_key.get(("http_service",service))
            if parent is None: parent = host_parent(p.hostname)
        else:
            candidates = [d.get("url"),d.get("form_action"),d.get("script"),d.get("hostname")]
            for value in candidates:
                if not value: continue
                for key in (("url",value),("http_service",value),("subdomain",value),("domain",value)):
                    if key in by_key:
                        parent = by_key[key]; break
                if parent is not None: break
            if parent is None:
                candidate_url = d.get("url") or d.get("form_action") or a.value
                host = urlsplit(str(candidate_url) if "://" in str(candidate_url) else "//"+str(candidate_url)).hostname
                parent = host_parent(host)
        if parent is not None and parent != i: edges.add((parent,i))

    # Preserve only grounded relationships. Isolated assets remain visible and selectable;
    # they are not falsely attached to an unrelated target in multi-target scans.
    priority = sorted(range(len(records)), key=lambda i:(layer.get(records[i].kind,3),i))[:260]
    remap = {old:new for new,old in enumerate(priority)}
    nodes=[]
    for i in priority:
        a=records[i]; label=a.value
        if a.kind in ("parameter","route"): label=f"{a.kind}: {a.value}"
        nodes.append({"asset":a,"label":label,"pos":positions[i],"color":KIND_COLORS.get(a.kind,"#9aaec8"),"size":16 if i in roots else (10 if layer.get(a.kind,3)<=2 else 7),"root":i in roots})
    edge_list=[(remap[a],remap[b]) for a,b in edges if a in remap and b in remap]
    return nodes,edge_list

