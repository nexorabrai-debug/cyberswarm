import getpass, os
from .store import Store
def _pw():
    pw = os.environ.get("CONTROL_PASSWORD")
    if pw: return pw
    a, b = getpass.getpass("Senha (mín. 10): "), getpass.getpass("Repita: ")
    if a != b: raise SystemExit("senhas diferentes")
    return a
def control_main(a):
    if a.action == "serve":
        from .server import serve
        secure = a.secure_cookie or a.tls or os.environ.get("CONTROL_SECURE_COOKIE", "").lower() in ("1", "true", "yes")
        allow = a.allow_lan or os.environ.get("CONTROL_ALLOW_LAN", "").lower() in ("1", "true", "yes")
        return serve(a.data, host=a.host, port=a.port, allow_lan=allow, secure_cookie=secure,
                     tls=getattr(a, "tls", False), cert=getattr(a, "cert", None), key=getattr(a, "key", None),
                     autostart=not getattr(a, "no_workers", False))
    st = Store(os.path.join(a.data, "control.db"))
    if a.action == "init":
        if st.q("SELECT id FROM users WHERE role='owner'"): raise SystemExit("já existe um owner; use adduser")
        st.add_user(a.user or "dono", _pw(), "owner"); print("owner criado:", a.user or "dono"); return 0
    if not a.user: raise SystemExit("--user obrigatório")
    st.add_user(a.user, _pw(), a.role, a.clients_only.split(",") if a.clients_only else None); print("usuário criado:", a.user, a.role); return 0
