"""Append-only, hash-chained audit log (tamper-evident)."""
import hashlib, json, time
from pathlib import Path


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev = "0" * 64
        self.seq = 0

    def log(self, event, **data):
        self.seq += 1
        entry = {"seq": self.seq, "ts": round(time.time(), 3), "event": event, "data": data, "prev": self.prev}
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()
        entry["hash"] = digest
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        self.prev = digest
        return entry


def verify_chain(path):
    """Return (ok, message). Detects edited, removed or reordered entries."""
    prev = "0" * 64
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        entry = json.loads(line)
        claimed = entry.pop("hash")
        if entry["prev"] != prev:
            return False, f"chain broken at line {n}"
        actual = hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()
        if actual != claimed:
            return False, f"entry modified at line {n}"
        prev = claimed
    return True, "audit chain intact"
