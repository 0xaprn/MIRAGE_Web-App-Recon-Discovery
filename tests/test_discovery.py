import unittest
from mirage.discovery import PageParser

class ParserTests(unittest.TestCase):
    def test_extracts_links_scripts_and_forms(self):
        p=PageParser("https://example.com/a")
        p.feed('''<a href="/users?id=2">users</a><script src="/static/app.js"></script><form action="/login" method="post"><input name="user" required><input name="pass" type="password"></form>''')
        self.assertIn("https://example.com/users?id=2",p.links)
        self.assertIn("https://example.com/static/app.js",p.scripts)
        self.assertEqual(p.forms[0]["method"],"post")
        self.assertEqual(len(p.forms[0]["fields"]),2)

if __name__=="__main__": unittest.main()

class ScopeRedirectTests(unittest.TestCase):
    def test_redirect_outside_scope_is_blocked(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from mirage.discovery import Discovery
        from mirage.scope import Scope
        seen=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header("Location",f"http://127.0.0.2:{self.server.server_port}/outside")
                self.end_headers()
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            url=f"http://127.0.0.1:{server.server_port}/redirect"
            d=Discovery(Scope(url),timeout=2)
            result=d.probe_http(url)
            self.assertIsNotNone(result)
            self.assertEqual(result[1]["status"],302)
            self.assertEqual(seen,["/redirect"])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

class LocalCrawlerTests(unittest.TestCase):
    def test_crawler_maps_routes_forms_and_scripts(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from mirage.discovery import Discovery
        from mirage.scope import Scope
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path=="/static/app.js":
                    body=b"fetch('/api/v1/users');"
                    ctype="application/javascript"
                else:
                    body=b'<html><a href="/profile?id=9">profile</a><script src="/static/app.js"></script><form action="/search" method="get"><input name="q"></form></html>'
                    ctype="text/html"
                self.send_response(200); self.send_header("Content-Type",ctype); self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            url=f"http://127.0.0.1:{server.server_port}/"
            d=Discovery(Scope(url),timeout=2,concurrency=3,max_pages=10,max_depth=2,delay=0)
            assets,findings,errors=d.crawl([url]),d.findings,d.errors
            kinds={(a.kind,a.value) for a in d.assets}
            self.assertIn(("parameter","q"),kinds)
            self.assertIn(("parameter","id"),kinds)
            self.assertTrue(any(k=="javascript" for k,v in kinds))
            self.assertTrue(any(k=="api_candidate" for k,v in kinds))
            self.assertFalse(errors)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

class EngineIPTargetIntegrationTests(unittest.TestCase):
    def test_ip_literal_target_scans_local_http_fixture(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from mirage.engine import Engine

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'<html><a href="/panel?view=1">panel</a></html>'
                self.send_response(200)
                self.send_header('Content-Type','text/html; charset=utf-8')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass

        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            url=f'http://127.0.0.1:{server.server_port}/'
            result=Engine(timeout=1,concurrency=3,max_pages=8,max_depth=2,delay=0,ports=[server.server_port]).scan(url,save=False)
            kinds={(a.kind,a.value) for a in result.assets}
            self.assertIn(('ip','127.0.0.1'),kinds)
            self.assertTrue(any(k=='route' and v=='/panel' for k,v in kinds))
            self.assertTrue(any(k=='tcp_service' and v.endswith(f':{server.server_port}') for k,v in kinds))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


class SecurityAssessmentTests(unittest.TestCase):
    def test_header_assessment_emits_specific_findings(self):
        from mirage.discovery import Discovery
        from mirage.scope import Scope
        d=Discovery(Scope("https://example.com"),delay=0)
        d.inspect_headers("https://example.com/login", {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
            "set-cookie": "session=abc; Path=/",
            "server": "Apache/2.4.49",
            "x-powered-by": "PHP/7.4.3",
            "strict-transport-security": "max-age=3600",
        })
        titles={f.title for f in d.findings}
        self.assertIn("Content Security Policy permits unsafe script execution",titles)
        self.assertIn("Cookie missing security attributes",titles)
        self.assertIn("Server version disclosed",titles)
        self.assertIn("Short HSTS max-age",titles)

    def test_password_form_over_http_is_flagged_without_submission(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from mirage.discovery import Discovery
        from mirage.scope import Scope
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'<form action="/login" method="post"><input name="password" type="password"></form>'
                self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers(); self.wfile.write(body)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            url=f"http://127.0.0.1:{server.server_port}/"
            d=Discovery(Scope(url),timeout=2,concurrency=2,max_pages=4,max_depth=1,delay=0)
            d.crawl([url])
            self.assertTrue(any(f.title=="Password form served over HTTP" for f in d.findings))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

class VulnerabilityIntelTests(unittest.TestCase):
    def test_version_bearing_technology_banner_becomes_nvd_query(self):
        from mirage.models import Asset
        from mirage.vulnintel import _component_queries
        assets=[Asset("technology_hint","Apache/2.4.49","http-header",details={"url":"https://example.com"})]
        self.assertEqual(list(_component_queries(assets)),[("Apache HTTP Server 2.4.49","https://example.com")])
