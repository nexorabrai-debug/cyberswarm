import json, logging, sys, time
class JsonFormatter(logging.Formatter):
    def format(self, r):
        return json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "level": r.levelname, "logger": r.name, "msg": r.getMessage()}, ensure_ascii=False)
def get_logger(name="cyberswarm"):
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler(sys.stderr); h.setFormatter(JsonFormatter()); lg.addHandler(h); lg.setLevel(logging.INFO)
    return lg
