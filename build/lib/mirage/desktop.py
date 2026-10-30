from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .engine import Engine
from .models import ScanResult
from .report import write_html
from .topology import build_topology

WEB_ROOT = Path(__file__).with_name("webui")


class MirageDesktop:
    """Loopback-only desktop web shell backed by the real MIRAGE discovery engine."""
    def __init__(self, db_path="~/.local/share/mirage/mirage.sqlite3"):
        self.db_path = db_path
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.state = {
            "running": False, "status": "READY", "stage": "Standing by", "started": None,
            "finished": None, "result": None, "logs": [], "error": None,
        }
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "MIRAGE-Desktop/0.3"
            def log_message(self, *_args):
                return

            def _send(self, code, body, content_type="application/json; charset=utf-8", headers=None):
                if isinstance(body, (dict, list)):
                    body = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
                elif isinstance(body, str):
                    body = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
                for key, value in (headers or {}).items(): self.send_header(key, value)
                self.end_headers(); self.wfile.write(body)

            def _authorized(self):
                return secrets.compare_digest(self.headers.get("X-Mirage-Token", ""), owner.token)

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    self._send(200, (WEB_ROOT / "index.html").read_text(encoding="utf-8"), "text/html; charset=utf-8"); return
                if parsed.path in ("/app.css", "/app.js"):
                    path = WEB_ROOT / parsed.path.lstrip("/")
                    if not path.is_file(): self._send(404, "Not found", "text/plain"); return
                    kind = "text/css; charset=utf-8" if path.suffix == ".css" else "text/javascript; charset=utf-8"
                    self._send(200, path.read_text(encoding="utf-8"), kind); return
                if parsed.path.startswith("/api/") and not self._authorized():
                    self._send(403, {"error": "Invalid desktop session token"}); return
                if parsed.path == "/api/state":
                    with owner.lock:
                        s = owner.state
                        result = s["result"]
                        payload = {
                            "running": s["running"], "status": s["status"], "stage": s["stage"],
                            "started": s["started"], "finished": s["finished"], "error": s["error"],
                            "logs": s["logs"][-100:],
                            "counts": result.stats if result else {"assets":0,"findings":0,"errors":0,"subdomains":0,"http_services":0,"tcp_services":0},
                            "target": result.target if result else "",
                        }
                    self._send(200, payload); return
                if parsed.path == "/api/result":
                    with owner.lock: result = owner.state["result"]
                    if result is None: self._send(200, {"nodes":[],"edges":[],"assets":[],"findings":[]}); return
                    nodes, edges = build_topology(result.assets, result.target)
                    node_data = [{"label":n["label"],"kind":n["asset"].kind,"value":n["asset"].value,"source":n["asset"].source,"status":n["asset"].status,"details":n["asset"].details,"pos":n["pos"],"color":n["color"],"root":n["root"]} for n in nodes]
                    payload = {"nodes":node_data,"edges":edges,"assets":[a.__dict__ for a in result.assets],"findings":[f.__dict__ for f in result.findings]}
                    self._send(200, payload); return
                if parsed.path == "/api/export":
                    params=parse_qs(parsed.query); fmt=params.get("format",["json"])[0]
                    with owner.lock: result=owner.state["result"]
                    if result is None: self._send(409,{"error":"No completed scan to export"}); return
                    if fmt == "json":
                        body=result.to_json()
                        self._send(200,body,"application/json; charset=utf-8",{"Content-Disposition":f'attachment; filename="mirage-{result.scan_id}.json"'}); return
                    if fmt == "html":
                        import tempfile
                        with tempfile.NamedTemporaryFile(suffix=".html") as f:
                            write_html(result,f.name); body=Path(f.name).read_bytes()
                        self._send(200,body,"text/html; charset=utf-8",{"Content-Disposition":f'attachment; filename="mirage-{result.scan_id}.html"'}); return
                    self._send(400,{"error":"format must be json or html"}); return
                self._send(404,"Not found","text/plain")

            def do_POST(self):
                if not self._authorized(): self._send(403,{"error":"Invalid desktop session token"}); return
                if urlparse(self.path).path != "/api/start": self._send(404,{"error":"Not found"}); return
                try:
                    size=int(self.headers.get("Content-Length","0"))
                    if size > 1_000_000: raise ValueError("Request body too large")
                    payload=json.loads(self.rfile.read(size) or b"{}")
                    targets=payload.get("targets") or [payload.get("target","")]
                    targets=[str(x).strip() for x in targets if str(x).strip()]
                    if not targets: raise ValueError("At least one target is required")
                    config=payload.get("config",{})
                    pages=max(1,min(int(config.get("pages",500)),10000))
                    workers=max(1,min(int(config.get("workers",24)),32))
                    depth=max(0,min(int(config.get("depth",5)),12))
                    timeout=max(.5,min(float(config.get("timeout",5)),60))
                    delay=max(0,min(float(config.get("delay",.12)),10))
                    ports=config.get("ports") or None
                    cve_intel=bool(config.get("cve_intel", True))
                    if ports is not None:
                        from .cli import parse_ports
                        ports=parse_ports(str(ports) if isinstance(ports,str) else ",".join(str(x) for x in ports))
                    if len(targets)>256: raise ValueError("A batch is limited to 256 targets per operation")
                    with owner.lock:
                        if owner.state["running"]: self._send(409,{"error":"A scan is already running"}); return
                        owner.state.update({"running":True,"status":"RUNNING","stage":"Initializing discovery engines","started":time.time(),"finished":None,"result":None,"logs":[],"error":None})
                    thread=threading.Thread(target=owner._run_scan,args=(targets,pages,workers,depth,timeout,delay,ports,cve_intel),daemon=True,name="mirage-web-discovery")
                    thread.start()
                    self._send(202,{"accepted":True,"targets":len(targets)})
                except Exception as exc:
                    self._send(400,{"error":str(exc)})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True

    def _log(self, message, level="INFO"):
        item={"time":datetime.now().strftime("%H:%M:%S"),"level":level,"message":str(message)}
        with self.lock:
            self.state["logs"].append(item)
            self.state["logs"]=self.state["logs"][-500:]
            self.state["stage"]=str(message)

    def _run_scan(self, targets, pages, workers, depth, timeout, delay, ports, cve_intel=True):
        started=datetime.now(timezone.utc).isoformat(timespec="seconds")
        all_assets=[]; all_findings=[]; all_errors=[]; target_stats=[]
        engine=Engine(db_path=self.db_path,timeout=timeout,concurrency=workers,max_pages=pages,max_depth=depth,delay=delay,ports=ports,cve_intel=cve_intel)
        try:
            for index,target in enumerate(targets,1):
                self._log(f"Target {index}/{len(targets)} · {target}")
                try:
                    result=engine.scan(target,progress=lambda msg:self._log(msg))
                    all_assets.extend(result.assets); all_findings.extend(result.findings); all_errors.extend(result.errors)
                    target_stats.append({"target":target,"scan_id":result.scan_id,"assets":len(result.assets),"findings":len(result.findings)})
                except Exception as exc:
                    all_errors.append(f"{target}: {exc}"); target_stats.append({"target":target,"error":str(exc)})
                    self._log(f"Target failed · {target} · {exc}","ERROR")
            unique_assets={}
            for asset in all_assets: unique_assets.setdefault((asset.kind,asset.value),asset)
            unique_findings={}
            for finding in all_findings: unique_findings.setdefault((finding.title,finding.asset),finding)
            assets=list(unique_assets.values()); findings=list(unique_findings.values())
            finished=datetime.now(timezone.utc).isoformat(timespec="seconds")
            from collections import Counter
            counts=Counter(a.kind for a in assets)
            aggregate=ScanResult("batch-"+secrets.token_hex(5),", ".join(targets),started,finished,assets,findings,all_errors,{
                "assets":len(assets),"findings":len(findings),"errors":len(all_errors),
                "subdomains":counts.get("subdomain",0),"http_services":counts.get("http_service",0),"tcp_services":counts.get("tcp_service",0),
                "hosts":counts.get("domain",0)+counts.get("subdomain",0)+counts.get("ip",0),"targets":target_stats,
            })
            with self.lock:
                self.state.update({"running":False,"status":"COMPLETE","stage":"Discovery completed","finished":time.time(),"result":aggregate})
            self._log(f"Completed · {len(assets)} assets · {len(findings)} potential findings · {len(all_errors)} errors","SUCCESS")
        except Exception as exc:
            with self.lock:
                self.state.update({"running":False,"status":"FAILED","error":str(exc),"finished":time.time()})
            self._log(f"Scan failed · {exc}","ERROR")

    def run(self):
        host,port=self.httpd.server_address
        url=f"http://{host}:{port}/#token={self.token}"
        browser=shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        print("MIRAGE 0.5.0 desktop console",flush=True)
        print(f"Local-only interface: {url}",flush=True)
        if browser:
            try: subprocess.Popen([browser,"--app="+url,"--new-window"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            except OSError: webbrowser.open(url)
        else:
            webbrowser.open(url)
        print("Keep this process running while using MIRAGE. Press Ctrl+C to close the local desktop service.",flush=True)
        try: self.httpd.serve_forever(poll_interval=.25)
        except KeyboardInterrupt: pass
        finally: self.httpd.shutdown(); self.httpd.server_close()


def main():
    MirageDesktop().run()
