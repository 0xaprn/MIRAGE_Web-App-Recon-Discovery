from __future__ import annotations
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .discovery import Discovery
from .models import ScanResult
from .scope import Scope
from .store import Store

DEFAULT_WORDS = ["www","api","dev","stage","staging","test","admin","portal","app","auth","login","beta","old","vpn","mail","support","docs","cdn","static","assets","dashboard","internal"]

class Engine:
    def __init__(self, db_path: str | Path = "~/.local/share/mirage/mirage.sqlite3", timeout=5, concurrency=12, max_pages=150, max_depth=3, delay=.15, ports=None, cve_intel=False):
        self.db_path=Path(db_path).expanduser()
        if timeout<=0 or concurrency<1 or max_pages<1 or max_depth<0 or delay<0:
            raise ValueError("Timeout and concurrency must be positive; page/depth/delay limits cannot be negative")
        self.timeout,self.concurrency,self.max_pages,self.max_depth,self.delay=timeout,concurrency,max_pages,max_depth,delay
        self.ports=ports
        self.cve_intel=bool(cve_intel)
    def scan(self, target: str, wordlist: list[str] | None = None, progress=None, save=True) -> ScanResult:
        scope=Scope(target)
        started=datetime.now(timezone.utc).isoformat(timespec="seconds")
        result=ScanResult(uuid.uuid4().hex[:12],target,started)
        # Keep IP literals/CIDRs in the explicit network set. Discovery expands only
        # the permitted range and brackets IPv6 hosts when constructing URLs.
        roots=scope.roots
        target_urls=list(scope.urls)
        worker=Discovery(scope,self.timeout,self.concurrency,self.max_pages,self.max_depth,self.delay,self.ports)
        assets,findings,errors=worker.run(target_urls,roots,wordlist if wordlist is not None else DEFAULT_WORDS,progress)
        if self.cve_intel:
            from .vulnintel import enrich_findings
            findings.extend(enrich_findings(assets, progress=progress, timeout=self.timeout))
        result.assets,result.findings,result.errors=assets,findings,errors
        result.finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds")
        result.stats={
            "assets":len(assets),
            "findings":len(findings),
            "errors":len(errors),
            "scope":scope.describe(),
            "pages_fetched":sum(1 for a in assets if a.kind=="url" and a.status.isdigit()),
            "urls_discovered":sum(1 for a in assets if a.kind=="url"),
            "subdomains":sum(1 for a in assets if a.kind=="subdomain"),
            "http_services":sum(1 for a in assets if a.kind=="http_service"),
            "tcp_services":sum(1 for a in assets if a.kind=="tcp_service"),
        }
        if save:
            store=Store(self.db_path)
            try: store.save(result)
            finally: store.close()
        return result
