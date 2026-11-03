"""iOS auditor: static Info.plist checks."""
import asyncio, os, plistlib
from ..registry import Agent, register
from .common import file_proof, file_repro, find_line
@register
class IosAuditor(Agent):
    name = "ios"; kind = "path"
    async def run(self, target): return await asyncio.to_thread(self._run, target)
    def _run(self, target):
        self.scope.check_path(target)
        p = os.path.join(target, "Info.plist") if os.path.isdir(target) else target
        self.scope.check_path(p); self.audit.log("read_file", agent=self.name, path=p)
        raw = open(p, "rb").read(); d = plistlib.loads(raw); out = []
        try: lines = raw.decode().splitlines()
        except UnicodeDecodeError: lines = []  # binary plist: no line numbers -> suspeita
        def add(cid, needle, ev, detail="", start=0):
            n = find_line(lines, needle, start); out.append(self.finding(cid, p, ev, file_proof(p, lines, n), detail, file_repro(p, n)))
        ats = d.get("NSAppTransportSecurity") or {}
        if ats.get("NSAllowsArbitraryLoads"): add("ios.ats_disabled", "<key>NSAllowsArbitraryLoads</key>", "NSAllowsArbitraryLoads = true")
        if ats.get("NSAllowsArbitraryLoadsInWebContent"): add("ios.ats_webcontent", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsInWebContent = true")
        for dom, cfg in (ats.get("NSExceptionDomains") or {}).items():
            dl = find_line(lines, f"<key>{dom}</key>")
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads"): add("ios.insecure_domain", "NSExceptionAllowsInsecureHTTPLoads", f"{dom}: NSExceptionAllowsInsecureHTTPLoads = true", dom, dl)
            v = str(cfg.get("NSExceptionMinimumTLSVersion", ""))
            if v in ("TLSv1.0", "TLSv1.1"): add("ios.old_tls_domain", "NSExceptionMinimumTLSVersion", f"{dom}: NSExceptionMinimumTLSVersion = {v}", dom, dl)
        if d.get("UIFileSharingEnabled"): add("ios.file_sharing", "<key>UIFileSharingEnabled</key>", "UIFileSharingEnabled = true")
        for t in d.get("CFBundleURLTypes") or []:
            for s in t.get("CFBundleURLSchemes") or []: add("ios.url_scheme", f"<string>{s}</string>", f"CFBundleURLSchemes = {s}", f"{s}://")
        return out
