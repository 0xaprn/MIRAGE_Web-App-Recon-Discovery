from __future__ import annotations
import concurrent.futures, ipaddress, json, socket, ssl, urllib.error, urllib.parse, urllib.request, xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Callable
from .models import Asset, Finding
from .scope import Scope

UA = "MIRAGE/0.2 (+security-research; contact: operator)"

class PageParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: set[str] = set(); self.scripts: set[str] = set(); self.forms: list[dict] = []
        self._form: dict | None = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"): self.links.add(urllib.parse.urljoin(self.base, a["href"]))
        if tag == "script" and a.get("src"): self.scripts.add(urllib.parse.urljoin(self.base, a["src"]))
        if tag == "form":
            self._form = {"action": urllib.parse.urljoin(self.base, a.get("action", self.base)), "method": a.get("method", "get").lower(), "fields": []}
        if self._form is not None and tag in ("input", "select", "textarea", "button"):
            self._form["fields"].append({"name": a.get("name", ""), "type": a.get("type", tag), "required": "required" in a})
    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form); self._form = None

class Discovery:
    def __init__(self, scope: Scope, timeout: float = 5.0, concurrency: int = 12, max_pages: int = 150, max_depth: int = 3, delay: float = 0.15, ports: list[int] | None = None):
        self.scope, self.timeout, self.concurrency = scope, timeout, max(1, min(concurrency, 32))
        self.max_pages, self.max_depth, self.delay = max(1,max_pages), max(0,max_depth), max(0.0, delay)
        self.ports = ports
        self.assets: list[Asset] = []; self.findings: list[Finding] = []; self.errors: list[str] = []
        self._seen: set[tuple[str,str]] = set(); self._tls_seen: set[str] = set()
    def add(self, kind, value, source, status="observed", **details):
        key=(kind,value)
        if key not in self._seen:
            self._seen.add(key); self.assets.append(Asset(kind,value,source,status,details))
    def resolve(self, host: str, source="dns") -> list[str]:
        try:
            infos=socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ips=sorted({i[4][0] for i in infos})
            for ip in ips: self.add("ip",ip,source,hostname=host)
            return ips
        except OSError as e:
            self.errors.append(f"DNS {host}: {e}"); return []
    def dns_records(self, host: str):
        """Collect common DNS RRsets when dnspython is installed; fall back to the OS resolver."""
        self.resolve(host)
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=True)
            resolver.lifetime = self.timeout
            for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"):
                try:
                    answer = resolver.resolve(host, record_type, lifetime=self.timeout, raise_on_no_answer=False)
                    if answer.rrset is None:
                        continue
                    for item in answer:
                        value = item.to_text()
                        self.add("dns_record", f"{host} {record_type} {value}", "dns-resolver", record_type=record_type, hostname=host, ttl=answer.rrset.ttl)
                except Exception:
                    # NODATA and NXDOMAIN are normal for many RR types; timeout/errors are captured once at host level below.
                    continue
        except ImportError:
            self.add("discovery_note", "dnspython unavailable; only system A/AAAA resolution was performed", "dns-resolver", hostname=host)
    def passive_ct(self, root: str):
        url="https://crt.sh/?q=%25."+urllib.parse.quote(root)+"&output=json"
        try:
            req=urllib.request.Request(url, headers={"User-Agent":UA})
            with urllib.request.urlopen(req, timeout=self.timeout) as r: data=json.loads(r.read(5_000_000))
            names=set()
            for row in data:
                for name in row.get("name_value", "").splitlines():
                    name=name.strip().lower().lstrip("*.")
                    if self.scope.allows_host(name): names.add(name)
            for name in sorted(names): self.add("subdomain",name,"certificate-transparency")
        except Exception as e: self.errors.append(f"Certificate Transparency {root}: {e}")
    def enumerate_subdomains(self, root: str, wordlist: list[str], progress=None):
        candidates=[f"{w.strip()}.{root}" for w in wordlist if w.strip()]
        if progress: progress(f"Enumerating {len(candidates)} DNS wordlist candidates for {root}")
        def check(host):
            try: return host, sorted({x[4][0] for x in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
            except OSError: return host, []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for index,(host,ips) in enumerate(pool.map(check,candidates),1):
                if ips and self.scope.allows_host(host):
                    self.add("subdomain",host,"dns-wordlist")
                    for ip in ips: self.add("ip",ip,"dns-resolution",hostname=host)
                if progress and (index % 20 == 0 or index == len(candidates)):
                    progress(f"DNS wordlist progress {index}/{len(candidates)} · {root}")
    def probe_http(self, url: str) -> tuple[str,dict,str] | None:
        if not self.scope.allows_url(url): return None
        req=urllib.request.Request(url, headers={"User-Agent":UA,"Accept":"text/html,application/json,*/*"}, method="GET")
        scope=self.scope
        class ScopedRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if not scope.allows_url(newurl):
                    raise urllib.error.HTTPError(newurl, code, "Redirect outside authorized scope blocked", headers, fp)
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        opener=urllib.request.build_opener(ScopedRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body=resp.read(1_000_000)
                headers={k.lower():v for k,v in resp.headers.items()}
                return resp.geturl(), {"status":resp.status,"headers":headers,"content_type":headers.get("content-type",""),"bytes_sampled":len(body)}, body.decode("utf-8","replace")
        except urllib.error.HTTPError as e:
            body=e.read(256_000)
            return url,{"status":e.code,"headers":{k.lower():v for k,v in e.headers.items()},"content_type":e.headers.get("Content-Type","")},body.decode("utf-8","replace")
        except Exception as e:
            self.errors.append(f"HTTP {url}: {e}"); return None
    def inspect_tls(self, url: str):
        import datetime, socket
        p=urllib.parse.urlsplit(url)
        if p.scheme!="https" or not p.hostname: return
        port=p.port or 443
        origin=f"https://{p.hostname}:{port}"
        if origin in self._tls_seen: return
        self._tls_seen.add(origin)
        try:
            context=ssl.create_default_context()
            with socket.create_connection((p.hostname,port),timeout=self.timeout) as raw:
                with context.wrap_socket(raw,server_hostname=p.hostname) as conn:
                    cert=conn.getpeercert()
                    expires=ssl.cert_time_to_seconds(cert["notAfter"])
                    expires_dt=datetime.datetime.fromtimestamp(expires,datetime.timezone.utc)
                    days=(expires_dt-datetime.datetime.now(datetime.timezone.utc)).days
                    details={"subject":cert.get("subject",()),"issuer":cert.get("issuer",()),"not_before":cert.get("notBefore"),"not_after":cert.get("notAfter"),"days_until_expiry":days,"subject_alt_names":cert.get("subjectAltName",()),"tls_version":conn.version(),"cipher":conn.cipher()}
                    self.add("tls_certificate",origin,"tls-handshake",**details)
                    if days<0:
                        self.findings.append(Finding("Expired TLS certificate","high","high",origin,"The certificate presented by the HTTPS service is expired.",details,"Renew and deploy a valid certificate."))
                    elif days<=14:
                        self.findings.append(Finding("TLS certificate nearing expiry","medium","high",origin,f"The certificate expires in approximately {days} days.",details,"Renew the certificate before expiration."))
        except Exception as e:
            self.errors.append(f"TLS {origin}: {e}")

    def inspect_headers(self, url: str, headers: dict):
        """Assess observable response controls; findings are configuration evidence, not exploit claims."""
        lower={k.lower():v for k,v in headers.items()}
        secure=url.startswith("https://")
        checks=[
            ("content-security-policy","Missing Content-Security-Policy", "low", False),
            ("x-content-type-options","Missing X-Content-Type-Options", "low", False),
            ("referrer-policy","Missing Referrer-Policy", "info", False),
            ("permissions-policy","Missing Permissions-Policy", "info", False),
            ("strict-transport-security","Missing HSTS on HTTPS", "medium", True),
        ]
        for header,title,severity,https_only in checks:
            if header not in lower and (secure or not https_only):
                self.findings.append(Finding(title,severity,"high" if severity in ("low","medium") else "medium",url,
                    f"The response did not include the {header} header.",{"url":url,"missing_header":header,"transport":"https" if secure else "http"},
                    "Review the application's threat model and configure an appropriate response policy."))
        csp=lower.get("content-security-policy","")
        if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
            directives=[x.strip() for x in csp.split(';') if "'unsafe-inline'" in x or "'unsafe-eval'" in x]
            self.findings.append(Finding("Content Security Policy permits unsafe script execution","medium","medium",url,
                "The Content-Security-Policy contains unsafe-inline or unsafe-eval in one or more directives. The impact depends on the affected directive and application behavior.",
                {"directives":directives,"csp":csp[:1200]},"Replace unsafe script allowances with nonces or hashes where feasible and remove unsafe-eval if not required."))
        hsts=lower.get("strict-transport-security","")
        if secure and hsts:
            import re
            age=re.search(r"max-age\s*=\s*(\d+)",hsts,re.I)
            if age and int(age.group(1)) < 15552000:
                self.findings.append(Finding("Short HSTS max-age","low","high",url,"The HSTS max-age is shorter than 180 days.",{"strict_transport_security":hsts,"max_age_seconds":int(age.group(1))},"Consider a longer HSTS max-age after validating HTTPS coverage across the domain."))
        for cookie in headers.get("Set-Cookie", headers.get("set-cookie", "")).split("\n"):
            if not cookie.strip(): continue
            name=cookie.split("=",1)[0].strip()
            flags=cookie.lower()
            missing=[flag for flag in ("secure","httponly","samesite") if flag not in flags]
            if missing:
                severity="medium" if "secure" in missing and secure else "low"
                self.findings.append(Finding("Cookie missing security attributes","%s"%severity,"high",url,
                    f"Cookie {name!r} is missing one or more recommended attributes.",{"cookie_name":name,"missing_attributes":missing,"secure_transport":secure},
                    "Set Secure on HTTPS cookies, HttpOnly where JavaScript access is unnecessary, and an intentional SameSite policy."))
        server=lower.get("server")
        if server:
            self.add("technology_hint",server,"http-header",url=url,header="server")
            import re
            if re.search(r"\d+\.\d+",server):
                self.findings.append(Finding("Server version disclosed","info","high",url,"The Server response header exposes a version-like product identifier. Version disclosure is not itself proof of a vulnerability.",{"server_header":server},"Consider minimizing unnecessary version disclosure and keep the component patched."))
        powered=lower.get("x-powered-by")
        if powered:
            self.add("technology_hint",powered,"http-header",url=url,header="x-powered-by")
            self.findings.append(Finding("Application technology disclosed","info","high",url,"The X-Powered-By header identifies application technology.",{"x_powered_by":powered},"Remove unnecessary technology-identification headers."))
        if lower.get("access-control-allow-origin") == "*":
            self.findings.append(Finding("Wildcard CORS origin policy","low","medium",url,"The response allows cross-origin requests from any origin. Whether this is exploitable depends on the data and authentication model.",{"access_control_allow_origin":"*","access_control_allow_credentials":lower.get("access-control-allow-credentials")},"Restrict allowed origins to the minimum set required by the application."))
    def inspect_common_exposures(self, base_urls: list[str], progress=None):
        """Check common read-only exposure paths using bounded concurrent GET requests."""
        import time
        paths = ("/.git/HEAD", "/.env", "/.DS_Store", "/phpinfo.php", "/server-status", "/swagger.json", "/openapi.json", "/api-docs", "/.well-known/security.txt")
        origins=[]
        for base in base_urls:
            p=urllib.parse.urlsplit(base)
            origin=f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""
            if origin and origin not in origins: origins.append(origin)
        jobs=[urllib.parse.urljoin(origin,path) for origin in origins for path in paths if self.scope.allows_url(urllib.parse.urljoin(origin,path))]
        def fetch(url):
            if self.delay: time.sleep(self.delay)
            return url,self.probe_http(url)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for index,(url,result) in enumerate(pool.map(fetch,jobs),1):
                if result:
                    final,meta,body=result
                    status=int(meta.get("status",0))
                    if status == 200:
                        sample=body[:12000].lower()
                        path=urllib.parse.urlsplit(final).path.lower()
                        confirmed_shape = (
                            (path.endswith("/.git/head") and "ref: refs/" in sample) or
                            (path.endswith("/.env") and "=" in sample and any(token in sample for token in ("_key", "_secret", "_password", "database", "token"))) or
                            (path.endswith("/phpinfo.php") and ("php version" in sample or "phpinfo()" in sample)) or
                            (path.endswith(("/swagger.json","/openapi.json","/api-docs")) and ("openapi" in sample or "swagger" in sample)) or
                            (path.endswith("/server-status") and "server uptime" in sample)
                        )
                        if confirmed_shape:
                            self.add("exposed_resource",final,"common-exposure-check",status=str(status),content_type=meta.get("content_type",""),sample=body[:500])
                            self.findings.append(Finding("Potentially exposed application resource","medium","medium",final,"The response content matches a common diagnostic, configuration, source-control or API-description resource. Confirm whether it discloses sensitive information.",{"status":status,"content_type":meta.get("content_type",""),"sample":body[:300]},"Restrict access to operational files and diagnostic endpoints; verify the response does not disclose sensitive data."))
                        if "index of /" in sample:
                            self.findings.append(Finding("Directory listing may be enabled","low","medium",final,"The response resembles a web-server directory index.",{"status":status,"sample":body[:300]},"Disable directory indexing where it is not intentionally required."))
                if progress and (index % 8 == 0 or index == len(jobs)):
                    progress(f"Checking common exposure paths {index}/{len(jobs)}")

    def crawl(self, start_urls: list[str], progress: Callable[[str],None] | None = None):
        import time
        queue=[(u,0) for u in start_urls if self.scope.allows_url(u)]
        visited=set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while queue and len(visited)<self.max_pages:
                batch=[]
                while queue and len(batch)<self.concurrency and len(visited)+len(batch)<self.max_pages:
                    url,depth=queue.pop(0); norm=urllib.parse.urldefrag(url)[0]
                    if norm not in visited and self.scope.allows_url(norm):
                        visited.add(norm); batch.append((norm,depth))
                if not batch: continue
                if progress: progress(f"Crawling {len(visited)}/{self.max_pages}: {batch[0][0]} (+{len(batch)-1} concurrent)")
                def fetch(item):
                    if self.delay: time.sleep(self.delay)
                    return item, self.probe_http(item[0])
                for (url,depth),result in pool.map(fetch,batch):
                    if not result: continue
                    final,meta,body=result
                    asset_details=dict(meta)
                    asset_status=str(asset_details.pop("status", "observed"))
                    self.add("url",final,"http-crawl",status=asset_status,**asset_details)
                    self.inspect_tls(final)
                    parsed_url=urllib.parse.urlsplit(final)
                    for param in sorted(set(urllib.parse.parse_qs(parsed_url.query,keep_blank_values=True))):
                        self.add("parameter",param,"url-query",url=final,location="query")
                    origin=urllib.parse.urlsplit(final)
                    self.add("http_service",f"{origin.scheme}://{origin.netloc}","http-crawl",status=str(meta["status"]))
                    self.inspect_headers(final,meta.get("headers",{}))
                    ct=meta.get("content_type","").lower()
                    if depth>=self.max_depth or not ("text/html" in ct or not ct): continue
                    parser=PageParser(final)
                    try: parser.feed(body)
                    except Exception: pass
                    for link in parser.links:
                        p=urllib.parse.urlsplit(link)
                        if self.scope.allows_url(link) and p.scheme in ("http","https"):
                            self.add("route",p.path or "/","html-link",url=link)
                            if len(visited)+len(queue)<self.max_pages: queue.append((link,depth+1))
                        elif p.hostname and self.scope.allows_host(p.hostname):
                            self.add("url",link,"html-link",status="not-fetched")
                    for script in parser.scripts:
                        if self.scope.allows_url(script):
                            self.add("javascript",script,"html-script")
                            self._inspect_js(script)
                    for form in parser.forms:
                        if self.scope.allows_url(form["action"]):
                            self.add("form",form["action"],"html-form",**form)
                            password_fields=[f for f in form["fields"] if f.get("type")=="password"]
                            if password_fields and urllib.parse.urlsplit(final).scheme != "https":
                                self.findings.append(Finding("Password form served over HTTP","high","high",final,
                                    "A page containing a password input was delivered over unencrypted HTTP. Credentials submitted by this form may be exposed in transit.",
                                    {"page":final,"form_action":form["action"],"method":form["method"],"password_fields":len(password_fields)},
                                    "Serve the login page and form action exclusively over HTTPS and enable HSTS."))
                            for field in form["fields"]:
                                if field.get("name"):
                                    self.add("parameter",field["name"],"html-form",form_action=form["action"],method=form["method"],field_type=field["type"])
    def _inspect_js(self, url: str):
        result=self.probe_http(url)
        if not result: return
        final,meta,body=result
        if len(body)>1_000_000: body=body[:1_000_000]
        import re
        for match in re.findall(r"(?:https?://[^\s\"'`<>]+|/(?:api|v[0-9]+|graphql)[^\s\"'`<>]*)",body,re.I):
            candidate=urllib.parse.urljoin(final,match.rstrip(")]} ,;"))
            if self.scope.allows_url(candidate): self.add("api_candidate",candidate,"javascript-static-analysis")
        if re.search(r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}",body,re.I):
            self.findings.append(Finding("Possible hard-coded secret in JavaScript","high","low",url,"A string resembles a credential or token assignment. This is an indicator only; verify ownership and validity manually.",{"script":url},"Rotate exposed credentials and move secrets to server-side storage if confirmed."))
    def run(self, target_urls: list[str], roots: list[str], wordlist: list[str], progress=None):
        for root in roots:
            self.add("domain",root,"target-input")
            if progress: progress(f"DNS intelligence · resolving records for {root}")
            self.dns_records(root)
            if progress: progress(f"Passive discovery · querying Certificate Transparency for {root}")
            self.passive_ct(root)
            if wordlist: self.enumerate_subdomains(root,wordlist,progress)
        hosts=set(roots)
        hosts.update(a.value for a in self.assets if a.kind=="subdomain")
        # Enrich discovered names with DNS RRsets, not just A/AAAA answers.
        for host in sorted(hosts - set(roots))[:200]:
            if progress: progress(f"Enriching DNS records for {host}")
            self.dns_records(host)
        ip_hosts={a.value for a in self.assets if a.kind=="ip"}
        for network in self.scope.networks:
            if network.num_addresses <= 256:
                ip_hosts.update(str(ip) for ip in network.hosts())
            elif network.num_addresses == 1:
                ip_hosts.add(str(network.network_address))
            else:
                self.errors.append(f"Large network {network} not expanded automatically; narrow the CIDR or provide an explicit target list")
        for ip in sorted(ip_hosts):
            self.add("ip",ip,"explicit-ip-target" if any(ipaddress.ip_address(ip) in n and n.num_addresses == 1 for n in self.scope.networks) else "cidr-expansion")
        urls=list(target_urls)
        urls.extend(self.scope.urls)
        for host in sorted(hosts):
            for scheme in ("https","http"):
                u=f"{scheme}://{host}/"
                if u not in urls: urls.append(u)
        explicit_networks=bool(self.scope.networks)
        if explicit_networks:
            for ip in sorted(ip_hosts):
                url_host=f"[{ip}]" if ":" in ip else ip
                for scheme in ("https","http"):
                    u=f"{scheme}://{url_host}/"
                    if u not in urls: urls.append(u)
        if len(urls)>self.max_pages:
            self.errors.append(f"{len(urls)} seed URLs exceed the crawler page budget ({self.max_pages}); some seeds will not be fetched")
        if progress: progress(f"Web application mapping · probing {len(set(urls))} seed URLs")
        self.crawl(list(dict.fromkeys(urls)),progress)
        service_origins=[a.value for a in self.assets if a.kind=="http_service"]
        if progress: progress(f"Application metadata · checking robots.txt and sitemap.xml on {len(service_origins)} services")
        sitemap_urls=self.inspect_well_known(service_origins)
        if sitemap_urls: self.crawl(list(dict.fromkeys(sitemap_urls)),progress)
        if explicit_networks and ip_hosts:
            if progress: progress(f"Infrastructure discovery · checking TCP services across {len(ip_hosts)} IP address(es)")
            self.scan_ports(sorted(ip_hosts),self.ports or [21,22,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,8888],progress)
        elif hosts:
            # Domain scopes stay conservative around shared hosting/CDN infrastructure.
            if progress: progress(f"Infrastructure discovery · checking common web ports across {len(hosts)} hostname(s)")
            self.scan_ports(sorted(hosts),self.ports or [80,443,8000,8080,8443,8888],progress)
        # Probe web protocols on discovered non-standard web ports as well as 80/443.
        web_ports={80:"http",443:"https",8000:"http",8080:"http",8443:"https",8888:"http"}
        extra_urls=[]
        for asset in self.assets:
            if asset.kind != "tcp_service": continue
            host,port_text=asset.value.rsplit(":",1)
            port=int(port_text)
            if port in web_ports:
                host=host.strip("[]")
                hostpart=f"[{host}]" if ":" in host else host
                default=(port==80 and web_ports[port]=="http") or (port==443 and web_ports[port]=="https")
                extra_urls.append(f"{web_ports[port]}://{hostpart}"+("" if default else f":{port}")+"/")
        if extra_urls:
            if progress: progress(f"Non-standard web services · probing {len(set(extra_urls))} discovered origins")
            self.crawl(list(dict.fromkeys(extra_urls)),progress)
        service_origins=[a.value for a in self.assets if a.kind=="http_service"]
        if progress: progress(f"Security surface checks · testing read-only exposure paths across {len(service_origins)} web services")
        self.inspect_common_exposures(service_origins,progress)
        return self.assets,self.findings,self.errors

    def scan_ports(self, hosts: list[str], ports: list[int], progress=None):
        """Rate-limited TCP connect checks. No protocol exploitation or payloads are sent."""
        import socket
        jobs=[(h,p) for h in hosts for p in ports]
        if progress: progress(f"Checking TCP services 0/{len(jobs)}")
        def check(job):
            host,port=job
            try:
                with socket.create_connection((host,port),timeout=min(self.timeout,0.8)):
                    return host,port,True
            except OSError: return host,port,False
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for idx,(host,port,opened) in enumerate(pool.map(check,jobs),1):
                if opened:
                    service_host=f"[{host}]" if ":" in host else host
                    self.add("tcp_service",f"{service_host}:{port}","tcp-connect",port=port,transport="tcp",method="connect-only")
                if progress and (idx % 10 == 0 or idx == len(jobs)):
                    progress(f"Checking TCP services {idx}/{len(jobs)}")

    def inspect_well_known(self, base_urls: list[str]) -> list[str]:
        import time
        sitemap_urls=[]
        origins=[]
        for base in base_urls:
            p=urllib.parse.urlsplit(base)
            origin=f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""
            if origin and origin not in origins: origins.append(origin)
        jobs=[(base,path,kind) for base in origins for path,kind in (("/robots.txt","robots"),("/sitemap.xml","sitemap"))]
        def fetch(job):
            base,path,kind=job
            if self.delay: time.sleep(self.delay)
            return job,self.probe_http(urllib.parse.urljoin(base,path))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            for (base,path,kind),result in pool.map(fetch,jobs):
                if not result: continue
                final,meta,body=result
                self.add(kind,final,"well-known-resource",status=str(meta["status"]))
                if kind=="robots" and meta["status"]==200:
                    for line in body.splitlines():
                        line=line.strip()
                        if line.lower().startswith(("disallow:","allow:")):
                            value=line.split(":",1)[1].strip()
                            if value.startswith("/"):
                                candidate=urllib.parse.urljoin(base,value)
                                self.add("robots_path",candidate,"robots.txt")
                if kind=="sitemap" and meta["status"]==200:
                    try:
                        root=ET.fromstring(body)
                        for el in root.iter():
                            if el.tag.endswith("loc") and el.text:
                                loc=el.text.strip()
                                if self.scope.allows_url(loc):
                                    self.add("url",loc,"sitemap")
                                    sitemap_urls.append(loc)
                    except ET.ParseError: self.errors.append(f"Invalid sitemap XML: {final}")
        return sitemap_urls
