# core/run_store.py
from __future__ import annotations
from dataclasses import asdict, is_dataclass
from pathlib import Path
import json
import time
import uuid

def _to_jsonable(obj):
    if is_dataclass(obj):
        return asdict(obj)
    return obj

class RunStore:
    """
    Stores a run as:
      runs/<run_id>/
        iter_00.json
        iter_01.json
        ...
        files/...
    """
    def __init__(self, base_dir: str = "runs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        self.run_dir = self.base_dir / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.files_dir = self.run_dir / "files"
        self.files_dir.mkdir(parents=True, exist_ok=True)

    def save_iteration(self, i: int, payload: dict) -> str:
        p = self.run_dir / f"iter_{i:02d}.json"
        p.write_text(json.dumps(payload, indent=2, default=_to_jsonable))
        return str(p)

    def save_text(self, name: str, text: str) -> str:
        p = self.files_dir / name
        p.write_text(text)
        return str(p)

    def save_bytes(self, name: str, data: bytes) -> str:
        p = self.files_dir / name
        p.write_bytes(data)
        return str(p)

    def path(self) -> str:
        return str(self.run_dir)
