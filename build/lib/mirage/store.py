from __future__ import annotations
import json, sqlite3
from pathlib import Path
from .models import ScanResult

class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, target TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, result_json TEXT NOT NULL)")
        self.db.commit()

    def save(self, result: ScanResult) -> None:
        self.db.execute("INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?)", (result.scan_id, result.target, result.started_at, result.finished_at, result.to_json()))
        self.db.commit()

    def list_scans(self) -> list[dict]:
        rows = self.db.execute("SELECT scan_id,target,started_at,finished_at FROM scans ORDER BY started_at DESC").fetchall()
        return [dict(zip(("scan_id","target","started_at","finished_at"), r)) for r in rows]

    def load(self, scan_id: str) -> dict | None:
        row = self.db.execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self) -> None:
        self.db.close()
