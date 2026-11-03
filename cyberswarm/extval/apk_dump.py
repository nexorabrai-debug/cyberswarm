"""Helper executed with the tools venv python (androguard). Reads an APK OFFLINE and writes text artifacts:
manifest.xml, strings.txt ('<classe>\t<string>'), calls.txt ('<classe>.<metodo> -> <api>'). No device, no network."""
import json, os, sys
from loguru import logger; logger.remove()
from androguard.misc import AnalyzeAPK
apk, out = sys.argv[1], sys.argv[2]; os.makedirs(out, exist_ok=True)
a, ds, dx = AnalyzeAPK(apk)
from lxml import etree
open(os.path.join(out, "manifest.xml"), "w").write(etree.tostring(a.get_android_manifest_xml(), pretty_print=True).decode())
APIS = ("Landroid/util/Log;", "Ljavax/crypto/Cipher;->getInstance", "Ljava/security/MessageDigest;->getInstance",
        "Landroid/webkit/WebSettings;->setJavaScriptEnabled", "Landroid/webkit/WebView;->addJavascriptInterface",
        "Landroid/os/Environment;->getExternalStorageDirectory", "Landroid/content/ClipboardManager;",
        "Landroid/content/Context;->openFileOutput", "Landroid/content/SharedPreferences$Editor;->putString",
        "Ljavax/crypto/spec/SecretKeySpec;-><init>", "Ljavax/crypto/spec/IvParameterSpec;-><init>",
        "Landroid/webkit/WebView;->loadUrl", "Landroid/content/Context;->sendBroadcast", "Landroid/telephony/SmsManager;")
with open(os.path.join(out, "strings.txt"), "w") as s, open(os.path.join(out, "calls.txt"), "w") as c:
    for cls in dx.get_classes():
        if cls.is_external(): continue
        cn = cls.name
        if cn.startswith(("Landroid/support/", "Landroidx/", "Lcom/google/")): continue
        for m in cls.get_methods():
            for _, callee, _ in m.get_xref_to():
                sig = f"{callee.class_name}->{callee.name}"
                if any(sig.startswith(x) or callee.class_name == x for x in APIS):
                    c.write(f"{cn}->{m.name} -> {sig}\n")
    for st in dx.get_strings():
        v = st.get_value()
        if not v or len(v) > 300: continue
        users = {x[0].name for x in st.get_xref_from()}
        users = [u for u in users if not u.startswith(("Landroid/support/", "Landroidx/", "Lcom/google/"))]
        for u in sorted(users): s.write(f"{u}\t{v!r}\n")
json.dump({"package": a.get_package(), "sha256": __import__("hashlib").sha256(open(apk, "rb").read()).hexdigest(),
           "debuggable": a.get_attribute_value("application", "debuggable"), "allowBackup": a.get_attribute_value("application", "allowBackup"),
           "min_sdk": a.get_min_sdk_version(), "target_sdk": a.get_target_sdk_version(), "permissions": a.get_permissions()},
          open(os.path.join(out, "meta.json"), "w"), indent=1)
print("ok")
