"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}


    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        import time
        import uuid

        rid = request_id or str(uuid.uuid4())
        self._open[rid] = time.perf_counter()

        self.logs.append({
            "request_id": rid,
            "user_id": user_id,
            "input": text,
            "input_timestamp": utc_now_iso(),
            "output": None,
            "blocked": None,
            "layer": None,
            "latency_ms": None,
        })
        return rid


    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        import time

        rid = request_id
        entry = None

        for log in reversed(self.logs):
            if log["user_id"] == user_id and log["output"] is None:
                if rid is None or log["request_id"] == rid:
                    entry = log
                    rid = log["request_id"]
                    break

        if entry is None:
            rid = self.record_input(
                user_id=user_id, text="", request_id=rid
            )
            entry = self.logs[-1]

        start = self._open.pop(rid, None)
        latency = (
            round((time.perf_counter() - start) * 1000, 3)
            if start is not None else None
        )

        entry.update({
            "output": text,
            "output_timestamp": utc_now_iso(),
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency,
        })
        return entry


    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
