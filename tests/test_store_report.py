import tempfile, unittest
from pathlib import Path
from mirage.models import ScanResult, Asset, Finding
from mirage.store import Store
from mirage.report import write_json, write_html

class PersistenceTests(unittest.TestCase):
    def test_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            r=ScanResult("abc123","example.com","2026-01-01T00:00:00+00:00",assets=[Asset("domain","example.com","input")])
            s=Store(Path(d)/"db.sqlite3"); s.save(r)
            self.assertEqual(s.load("abc123")["target"],"example.com")
            self.assertEqual(len(s.list_scans()),1); s.close()
    def test_reports(self):
        with tempfile.TemporaryDirectory() as d:
            r=ScanResult("abc123","example.com","now",assets=[Asset("domain","example.com","input")],findings=[Finding("Potential issue","low","low","https://example.com","Test")])
            jp=Path(d)/"r.json"; hp=Path(d)/"r.html"
            write_json(r,jp); write_html(r,hp)
            self.assertIn('"scan_id": "abc123"',jp.read_text())
            self.assertIn("Potential issue",hp.read_text())

if __name__=="__main__": unittest.main()
