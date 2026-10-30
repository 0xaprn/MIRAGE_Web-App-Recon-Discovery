from __future__ import annotations
import html, json
from pathlib import Path
from .models import ScanResult

def write_json(result: ScanResult, path: str | Path):
    Path(path).write_text(result.to_json()+"\n",encoding="utf-8")

def write_html(result: ScanResult, path: str | Path):
    esc=html.escape
    rows="\n".join(f"<tr><td>{esc(a.kind)}</td><td>{esc(a.value)}</td><td>{esc(a.source)}</td><td>{esc(a.status)}</td></tr>" for a in result.assets)
    finds="\n".join(f"<tr><td>{esc(f.severity)}</td><td>{esc(f.title)}</td><td>{esc(f.asset)}</td><td>{esc(f.confidence)}</td><td>{esc(f.description)}</td></tr>" for f in result.findings)
    doc=f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MIRAGE report {esc(result.scan_id)}</title><style>body{{background:#0b1018;color:#e6edf6;font:15px system-ui;margin:3rem}}h1,h2{{color:#8be9fd}}table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}td,th{{border:1px solid #283446;padding:.55rem;text-align:left;vertical-align:top}}th{{background:#172233}}.muted{{color:#9baabd}}code{{color:#f1fa8c}}</style><h1>MIRAGE · Scan report</h1><p class="muted">Target: <code>{esc(result.target)}</code> · Scan: {esc(result.scan_id)} · {esc(result.started_at)} – {esc(result.finished_at)}</p><h2>Summary</h2><p>{len(result.assets)} assets · {len(result.findings)} potential findings · {len(result.errors)} errors</p><h2>Assets</h2><table><tr><th>Type</th><th>Value</th><th>Source</th><th>Status</th></tr>{rows}</table><h2>Potential findings (manual validation required)</h2><table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Confidence</th><th>Description</th></tr>{finds}</table><h2>Errors and coverage limitations</h2><ul>{''.join('<li>'+esc(e)+'</li>' for e in result.errors)}</ul><p class="muted">Discovery is incomplete by nature. A potential finding is not a confirmed vulnerability. Validate all results within authorized scope.</p></html>'''
    Path(path).write_text(doc,encoding="utf-8")
