"""Append-only, hash-chained audit trail (JSON lines). Never log secrets: callers pass only ops/targets."""
import hashlib, json, os, threading, time
class Audit:
    def __init__(self, path):
        self.path = path; self.lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.prev = "0" * 64
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.strip(): self.prev = json.loads(line)["hash"]
    def log(self, op, **data):
        with self.lock:
            rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "op": op, **data, "prev": self.prev}
            rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            with open(self.path, "a") as f: f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.prev = rec["hash"]
def verify(path):
    prev = "0" * 64
    with open(path) as f:
        for i, line in enumerate(f, 1):
            rec = json.loads(line); h = rec.pop("hash")
            if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()).hexdigest() != h:
                return False, i
            prev = h
    return True, 0
