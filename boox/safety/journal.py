"""Write-ahead journal.

Every partition write records its intent to disk, and fsyncs, *before* any bytes
reach the device.  If the tool dies mid-operation -- crash, power loss, someone
pulling the cable -- the journal is what lets ``boox doctor`` say exactly which
partition was in flight and where its backup lives, instead of leaving the owner
to guess at a tablet that will not boot.

The format is append-only JSON Lines. It is meant to be readable with ``cat`` by
someone who is having a bad day.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

STATE_INTENT = "intent"
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_ROLLED_BACK = "rolled_back"


@dataclass(frozen=True)
class Entry:
    id: str
    ts: float
    state: str
    op: str
    partition: str
    fields: dict[str, Any]

    @property
    def when(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))

    def describe(self) -> str:
        detail = self.fields.get("source") or self.fields.get("error") or ""
        return f"{self.when}  {self.state:<11} {self.op:<7} {self.partition:<18} {detail}"


class Journal:
    """Append-only record of intended and completed device writes."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        # Durability matters more than speed here: the whole point is that the
        # record survives whatever kills the process a moment later.
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

    def begin(self, op: str, partition: str, **fields: Any) -> str:
        entry_id = uuid.uuid4().hex[:12]
        self._append(
            {
                "id": entry_id,
                "ts": time.time(),
                "state": STATE_INTENT,
                "op": op,
                "partition": partition,
                **fields,
            }
        )
        return entry_id

    def finish(self, entry_id: str, state: str, **fields: Any) -> None:
        self._append({"id": entry_id, "ts": time.time(), "state": state, **fields})

    def done(self, entry_id: str, **fields: Any) -> None:
        self.finish(entry_id, STATE_DONE, **fields)

    def failed(self, entry_id: str, error: str, **fields: Any) -> None:
        self.finish(entry_id, STATE_FAILED, error=error, **fields)

    def rolled_back(self, entry_id: str, **fields: Any) -> None:
        self.finish(entry_id, STATE_ROLLED_BACK, **fields)

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())

        def _iter() -> Iterator[dict[str, Any]]:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        # A torn final line means we died mid-append. Everything
                        # before it is still good, so keep what we can.
                        continue

        return _iter()

    def entries(self) -> list[Entry]:
        """Fold the append-only log into one entry per operation, latest state."""
        merged: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for record in self.records():
            entry_id = record.get("id")
            if not entry_id:
                continue
            if entry_id not in merged:
                merged[entry_id] = {}
                order.append(entry_id)
            merged[entry_id].update(record)
        out = []
        for entry_id in order:
            data = merged[entry_id]
            out.append(
                Entry(
                    id=entry_id,
                    ts=float(data.get("ts", 0)),
                    state=str(data.get("state", "?")),
                    op=str(data.get("op", "?")),
                    partition=str(data.get("partition", "?")),
                    fields={
                        k: v
                        for k, v in data.items()
                        if k not in {"id", "ts", "state", "op", "partition"}
                    },
                )
            )
        return out

    def unfinished(self) -> list[Entry]:
        """Operations that announced an intent and never reported an outcome.

        These are the dangerous ones: a partition may be half-written.
        """
        return [e for e in self.entries() if e.state == STATE_INTENT]

    def is_clean(self) -> bool:
        return not self.unfinished()
