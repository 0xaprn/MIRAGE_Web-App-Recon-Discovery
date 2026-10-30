from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import __version__
from .engine import Engine
from .report import write_html, write_json

def parse_ports(value: str) -> list[int]:
    ports=set()
    for item in value.split(","):
        item=item.strip()
        if not item: continue
        if "-" in item:
            parts=item.split("-",1)
            if len(parts)!=2 or not all(x.isdigit() for x in parts): raise argparse.ArgumentTypeError(f"Invalid port range: {item}")
            start,end=map(int,parts)
            if start<1 or end>65535 or start>end or end-start+1>4096: raise argparse.ArgumentTypeError(f"Port range out of bounds: {item}")
            ports.update(range(start,end+1))
        else:
            if not item.isdigit() or not 1<=int(item)<=65535: raise argparse.ArgumentTypeError(f"Invalid port: {item}")
            ports.add(int(item))
    if not ports: raise argparse.ArgumentTypeError("At least one port is required")
    return sorted(ports)

def parser():
    p=argparse.ArgumentParser(prog="mirage",description="MIRAGE scoped attack-surface discovery and web research")
    p.add_argument("target",nargs="?",help="Domain, URL, IP address or CIDR")
    p.add_argument("--targets-file",help="Text file containing one target per line")
    p.add_argument("--wordlist",help="Subdomain wordlist (one label per line)")
    p.add_argument("--db",default="~/.local/share/mirage/mirage.sqlite3",help="SQLite history database")
    p.add_argument("--json",dest="json_path",help="Write JSON report")
    p.add_argument("--html",dest="html_path",help="Write HTML report")
    p.add_argument("--timeout",type=float,default=5.0)
    p.add_argument("--concurrency",type=int,default=12)
    p.add_argument("--max-pages",type=int,default=150)
    p.add_argument("--max-depth",type=int,default=3)
    p.add_argument("--delay",type=float,default=.15,help="Minimum per-request delay in seconds")
    p.add_argument("--ports",type=parse_ports,help="Override TCP connect ports, e.g. 80,443,8000-8100")
    p.add_argument("--version",action="version",version=f"MIRAGE {__version__}")
    return p

def main(argv=None):
    args=parser().parse_args(argv)
    if not args.target and not args.targets_file:
        parser().print_help(); return 2
    targets=[]
    if args.target: targets.append(args.target)
    if args.targets_file:
        targets.extend(x.strip() for x in Path(args.targets_file).read_text().splitlines() if x.strip() and not x.lstrip().startswith("#"))
    words=Path(args.wordlist).read_text().splitlines() if args.wordlist else None
    engine=Engine(args.db,args.timeout,args.concurrency,args.max_pages,args.max_depth,args.delay,args.ports)
    failures=0
    for index,target in enumerate(dict.fromkeys(targets),1):
        print(f"\n[{index}/{len(set(targets))}] MIRAGE scan: {target}",flush=True)
        try:
            result=engine.scan(target,words,progress=lambda msg: print(f"  {msg}",flush=True))
            print(f"Completed: {result.stats['assets']} assets, {result.stats['findings']} potential findings, {result.stats['errors']} errors",flush=True)
            stem=f"mirage-{result.scan_id}"
            if args.json_path: write_json(result,args.json_path if len(targets)==1 else f"{Path(args.json_path).stem}-{result.scan_id}.json")
            if args.html_path: write_html(result,args.html_path if len(targets)==1 else f"{Path(args.html_path).stem}-{result.scan_id}.html")
            if not args.json_path and not args.html_path: print(result.to_json())
        except Exception as exc:
            failures+=1; print(f"ERROR: {target}: {exc}",file=sys.stderr)
    return 1 if failures else 0

if __name__=="__main__": raise SystemExit(main())
