"""Android auditor: static AndroidManifest.xml checks."""
import asyncio, os, xml.etree.ElementTree as ET
from ..registry import Agent, register
from .common import file_proof, file_repro, find_line
A = "{http://schemas.android.com/apk/res/android}"
@register
class MobileAuditor(Agent):
    name = "mobile"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target)
        p = os.path.join(target, "AndroidManifest.xml") if os.path.isdir(target) else target
        self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
        text = open(p).read(); lines = text.splitlines(); app = ET.fromstring(text).find("application"); out = []
        if app is None: return out
        g = lambda e, k: (e.get(A + k) or "").lower()
        def add(cid, needle, ev, detail=""):
            n = find_line(lines, needle); out.append(self.finding(cid, p, ev, file_proof(p, lines, n), detail, file_repro(p, n)))
        if g(app, "debuggable") == "true": add("android.debuggable", 'android:debuggable="true"', 'android:debuggable="true"')
        ab = g(app, "allowBackup")
        if ab == "true": add("android.allow_backup", 'android:allowBackup="true"', 'android:allowBackup="true"')
        elif ab == "":  # implicit default -> inferred, no line to point at -> suspeita
            out.append(self.finding("android.allow_backup", p, "allowBackup não definido (padrão do Android = true)", {}, "implícito"))
        if g(app, "usesCleartextTraffic") == "true": add("android.cleartext", 'android:usesCleartextTraffic="true"', 'usesCleartextTraffic="true"')
        for tag in ("activity", "service", "receiver", "provider"):
            for c in app.findall(tag):
                exp = g(c, "exported"); has_if = c.find("intent-filter") is not None; nm = c.get(A + "name")
                if (exp == "true" or (exp == "" and has_if)) and not c.get(A + "permission"):
                    if tag == "activity" and any(a.get(A + "name", "").endswith(".MAIN") for a in c.iter("action")): continue  # launcher
                    add("android.exported", f'android:name="{nm}"', f"{tag} {nm} exported={exp or 'implícito (intent-filter)'}", f"{tag} {nm}")
        return out
