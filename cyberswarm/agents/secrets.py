"""Secret detection: specific token patterns + keyword assignments + high-entropy strings, with placeholder filtering."""
import math, re
SPECIFIC = [
    ("secret.private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("secret.aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret.github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b")),
    ("secret.slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("secret.google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")),
    ("secret.llm_api_key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}")),
    ("secret.stripe_key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}")),
]
ASSIGN = re.compile(r"""(?i)\b[\w-]*(?:secret|password|passwd|pwd|token|api_?key)[\w-]*["']?\s*[:=]\s*["']([^"']{6,})["']""")
QUOTED = re.compile(r"""["']([A-Za-z0-9+/=_\-]{20,})["']""")
PLACEHOLDERS = ("changeme", "change_me", "example", "xxx", "your_", "your-", "yourkey", "placeholder", "dummy", "sample",
                "redacted", "****", "todo", "insert", "replace", "<", "${", "{{", "%(", "var.", "process.env", "os.environ", "getenv")
def is_placeholder(v):
    lv = v.lower()
    return any(p in lv for p in PLACEHOLDERS) or lv in ("password", "secret", "token", "none", "null", "true", "false") or len(set(v)) <= 3
def entropy(s):
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(ch) for ch in set(s))) if s else 0.0
ENTROPY_MIN = 4.0
def mask(v): return f"{v[:4]}****({len(v)} chars)"
def scan_text(text):
    """yield (check_id, lineno, value, masked_line)"""
    for n, line in enumerate(text.splitlines(), 1):
        hit = False
        for cid, rx in SPECIFIC:
            for m in rx.finditer(line):
                hit = True; yield cid, n, m.group(0), line.replace(m.group(0), mask(m.group(0)))
        if hit: continue
        m = ASSIGN.search(line)
        if m and not is_placeholder(m.group(1)):
            yield "secret.assignment", n, m.group(1), line.replace(m.group(1), mask(m.group(1))); continue
        for m in QUOTED.finditer(line):
            v = m.group(1)
            if is_placeholder(v) or re.fullmatch(r"[0-9a-fA-F-]+", v): continue  # hashes/uuids
            if entropy(v) >= ENTROPY_MIN and re.search(r"\d", v) and re.search(r"[A-Za-z]", v):
                yield "secret.high_entropy", n, v, line.replace(v, mask(v))
