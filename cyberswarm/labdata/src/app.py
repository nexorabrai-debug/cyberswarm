# LAB ONLY - intentionally insecure sample application for CyberSwarm SAST tests. Never deploy.
import hashlib, pickle, sqlite3, subprocess
import requests, yaml

def calc(expr):
    return eval(expr)

def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True)

def load_session(blob):
    return pickle.loads(blob)

def load_cfg(text):
    return yaml.load(text)

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def fetch(url):
    return requests.get(url, verify=False)

def find_user(db, name):
    return db.execute("SELECT * FROM users WHERE name = '%s'" % name)

def safe_examples(db, name, text):
    # these must NOT be reported
    db.execute("SELECT * FROM users WHERE name = ?", (name,))
    subprocess.run(["ls", "-l"])
    return yaml.safe_load(text), hashlib.sha256(b"x").hexdigest()

DEBUG = True
