"""Offline static APK analysis (androguard, run in the tools venv as a subprocess). Writes text artifacts and builds
FILE proofs (line + sha) on them, so the core validator re-checks every finding against the artifact on disk."""
import asyncio, hashlib, json, os, re, subprocess
from ..registry import Agent, register
from ..agents.common import file_proof
from ..tools import toolbins
DUMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apk_dump.py")
SECRETISH = re.compile(r"(?i)(secret|key|passw|token)")
def tools_python():
    for d in toolbins():
        p = os.path.join(d, "python")
        if os.path.exists(p): return p
    return None
def mobsf_category(rule, title):
    """Map a MobSF rule to OUR check id (used only for corroboration)."""
    r = (rule or "").lower(); t = (title or "").lower()
    if "debuggable" in r: return "apk.debuggable"
    if "allowbackup" in r: return "apk.allowbackup"
    if "explicitly_exported" in r or "exported" in r:
        return "apk.exported.provider" if "provider" in t else "apk.exported.receiver" if "receiver" in t else "apk.exported.activity"
    if "vulnerable_os_version" in r: return "apk.old_minsdk"
    if "webview" in r and "javascript" in (r + t): return "apk.webview_js"
    if "cbc" in r or "static_iv" in r: return "apk.static_iv"
    if "hardcoded" in r or "secret" in r: return "apk.hardcoded_key"
    if "log" in r: return "apk.log_sensitive"
    if "external_storage" in r or "sdcard" in r: return "apk.external_storage"
    if "cleartext" in r or "http" in r: return "apk.cleartext_http"
    return None
@register
class ApkAnalyzer(Agent):
    name = "apk"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, apk):
        self.scope.check_path(apk); py = tools_python()
        if not py: raise RuntimeError("androguard indisponível (venv de ferramentas ausente)")
        sha = hashlib.sha256(open(apk, "rb").read()).hexdigest()
        art = os.path.join(self.ctx.options.get("artifacts_dir", os.path.join(__import__("tempfile").gettempdir(), "cyberswarm-apk")), sha[:12])
        if not os.path.exists(os.path.join(art, "meta.json")):
            r = subprocess.run([py, DUMP, apk, art], capture_output=True, text=True, timeout=self.ctx.options.get("apk_timeout", 300))
            if r.returncode != 0: raise RuntimeError(f"androguard falhou: {r.stderr[-200:]}")
        self.audit.log("apk_analyzed", agent=self.name, sha256=sha, artifacts=art)
        man_p, str_p, call_p = (os.path.join(art, x) for x in ("manifest.xml", "strings.txt", "calls.txt"))
        man, strs, calls = (open(p).read().splitlines() for p in (man_p, str_p, call_p))
        out = []
        def add(cid, path, lines, i, ev, detail=""):
            masked = None if path != str_p else (lines[i].split("\t")[0] + "\t" + lines[i].split("\t")[-1][:4] + "****")
            out.append(self.finding(cid, apk, ev, file_proof(path, lines, i + 1, masked), detail, f"sed -n '{i+1}p' {path}"))
        for i, l in enumerate(man):
            if 'android:debuggable="true"' in l: add("apk.debuggable", man_p, man, i, "manifest: android:debuggable=\"true\"")
            if 'android:allowBackup="true"' in l: add("apk.allowbackup", man_p, man, i, "manifest: android:allowBackup=\"true\"")
            m = re.search(r'<(activity|receiver|provider|service)\b.*android:name="([^"]+)"', l)
            if m and 'android:exported="true"' in l and "android:permission" not in l and "Permission=" not in l:
                kind = {"activity": "activity", "receiver": "receiver", "provider": "provider"}.get(m.group(1))
                if kind: add(f"apk.exported.{kind}", man_p, man, i, f"{m.group(1)} {m.group(2)} exported=true sem permissão", m.group(2).split(".")[-1])
            m = re.search(r'android:minSdkVersion="(\d+)"', l)
            if m and int(m.group(1)) < 21: add("apk.old_minsdk", man_p, man, i, f"minSdkVersion={m.group(1)}")
        seen = set()
        def once(cid, key):
            if (cid, key) in seen: return False
            seen.add((cid, key)); return True
        cls_with = lambda api: {l.split("->")[0] for l in calls if api in l}
        crypto_cls = cls_with("Ljavax/crypto/spec/SecretKeySpec;-><init>"); iv_cls = cls_with("Ljavax/crypto/spec/IvParameterSpec;-><init>")
        for i, l in enumerate(strs):
            cls, _, val = l.partition("\t"); v = val.strip("'\"")
            if v.startswith("http://") and len(v) >= 7 and once("apk.cleartext_http", cls):
                add("apk.cleartext_http", str_p, strs, i, f"string '{v[:40]}' em {cls}", cls.split("/")[-1].rstrip(";"))
            if cls in crypto_cls and len(v) >= 16 and " " in v or (cls in crypto_cls and SECRETISH.search(v) and len(v) >= 12):
                if once("apk.hardcoded_key", cls): add("apk.hardcoded_key", str_p, strs, i, f"string candidata a chave em {cls} (valor mascarado: {v[:4]}****)", cls.split("/")[-1].rstrip(";"))
            if re.fullmatch(r"(?i)devadmin|backdoor|superadmin", v) and once("apk.backdoor_string", cls):
                add("apk.backdoor_string", str_p, strs, i, f"string '{v}' em {cls}", cls.split("/")[-1].rstrip(";"))
        for i, l in enumerate(calls):
            src = l.split(" -> ")[0]; cls = src.split("->")[0]
            if "setJavaScriptEnabled" in l and once("apk.webview_js", cls): add("apk.webview_js", call_p, calls, i, f"{src} chama setJavaScriptEnabled")
            if "getExternalStorageDirectory" in l and once("apk.external_storage", cls): add("apk.external_storage", call_p, calls, i, f"{src} usa getExternalStorageDirectory")
            if "Landroid/util/Log;" in l and re.search(r"(?i)login|postData|pass|cred", src) and once("apk.log_sensitive", cls):
                add("apk.log_sensitive", call_p, calls, i, f"{src} chama Log em fluxo de credenciais")
            if "SharedPreferences$Editor;->putString" in l and re.search(r"(?i)cred|pass|login", src) and once("apk.prefs_creds", cls):
                add("apk.prefs_creds", call_p, calls, i, f"{src} grava strings em SharedPreferences")
            if "SmsManager;->sendTextMessage" in l and once("apk.receiver_sms", cls) and any(cls.split("/")[-1].rstrip(";").split("$")[0] in m and 'exported="true"' in m and "<receiver" in m for m in man):
                add("apk.receiver_sms", call_p, calls, i, f"{src} (receiver exportado) envia SMS")
        return out
