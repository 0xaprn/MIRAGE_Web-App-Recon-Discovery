import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mirage.desktop import MirageDesktop

class DesktopServerTests(unittest.TestCase):
    def setUp(self):
        self.app=MirageDesktop(db_path=":memory:")
        self.thread=threading.Thread(target=self.app.httpd.serve_forever,daemon=True)
        self.thread.start()
        self.base=f'http://127.0.0.1:{self.app.httpd.server_address[1]}'

    def tearDown(self):
        self.app.httpd.shutdown();self.app.httpd.server_close();self.thread.join(timeout=2)

    def request(self,path,method='GET',payload=None):
        data=json.dumps(payload).encode() if payload is not None else None
        req=Request(self.base+path,data=data,headers={'X-Mirage-Token':self.app.token,'Content-Type':'application/json'},method=method)
        return urlopen(req,timeout=3)

    def test_local_server_requires_session_token_for_api(self):
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.base+'/api/state',timeout=2)
        self.assertEqual(caught.exception.code,403)
        with self.request('/api/state') as response:
            state=json.loads(response.read())
        self.assertEqual(state['status'],'READY')
        with urlopen(self.base+'/',timeout=2) as response:
            self.assertIn(b'MIRAGE',response.read())
        with urlopen(self.base+'/app.js',timeout=2) as response:
            self.assertIn(b'class Graph3D',response.read())

    def test_desktop_api_runs_a_scoped_local_fixture_scan(self):
        class Fixture(BaseHTTPRequestHandler):
            def do_GET(self):
                body=b'<html><a href="/panel?view=1">panel</a></html>'
                self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args): pass
        fixture=ThreadingHTTPServer(('127.0.0.1',0),Fixture)
        fixture_thread=threading.Thread(target=fixture.serve_forever,daemon=True);fixture_thread.start()
        try:
            target=f'http://127.0.0.1:{fixture.server_port}/'
            payload={'targets':[target],'config':{'pages':8,'workers':3,'depth':2,'timeout':1,'delay':0,'ports':str(fixture.server_port)}}
            with self.request('/api/start','POST',payload) as response:
                self.assertEqual(response.status,202)
            state=None
            for _ in range(80):
                with self.request('/api/state') as response: state=json.loads(response.read())
                if not state['running']: break
                time.sleep(.1)
            self.assertEqual(state['status'],'COMPLETE')
            with self.request('/api/result') as response: result=json.loads(response.read())
            self.assertTrue(any(a['kind']=='route' and a['value']=='/panel' for a in result['assets']))
            self.assertGreater(len(result['nodes']),0)
            self.assertGreater(len(result['edges']),0)
        finally:
            fixture.shutdown();fixture.server_close();fixture_thread.join(timeout=2)

if __name__=='__main__': unittest.main()
