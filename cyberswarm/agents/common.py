import hashlib, os
from ..scope import LABDATA
def sha(s): return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
def display_path(path):
    rp = os.path.realpath(path); lab = os.path.realpath(LABDATA)
    return "labdata/" + os.path.relpath(rp, lab) if rp.startswith(lab + os.sep) else rp
def find_line(lines, needle, start=0):
    for i in range(start, len(lines)):
        if needle in lines[i]: return i + 1
    return 0
def file_proof(path, lines, lineno, masked=None):
    if not lineno: return {}
    raw = lines[lineno - 1]
    return {"type": "file", "path": display_path(path), "abs": os.path.realpath(path), "line": lineno,
            "snippet": (masked if masked is not None else raw).strip()[:200], "line_sha": sha(raw)}
def file_repro(path, lineno):
    return f"Abrir {display_path(path)} na linha {lineno} (ex.: sed -n '{lineno}p' {display_path(path)})" if lineno else ""
