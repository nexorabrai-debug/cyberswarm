import os, sys, socket, tempfile, pytest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from cyberswarm.scope import Scope, LABDATA
from cyberswarm.audit import Audit
from cyberswarm.net import Net
from cyberswarm.log import get_logger
from cyberswarm.orchestrator import Ctx
from cyberswarm.registry import load_all
def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
@pytest.fixture
def ctx(tmp_path):
    sc = Scope.lab(); au = Audit(str(tmp_path / "audit.log"))
    return Ctx(sc, get_logger("test"), Net(sc, au, rate_per_sec=200), au, {})
@pytest.fixture
def run_agent(ctx):
    import asyncio
    R = load_all()
    def _r(name, target, c=None): return asyncio.run(R[name](c or ctx).run(target))
    return _r
@pytest.fixture
def lab_url():
    from cyberswarm.lab import start
    p = free_port(); srv = start(p); yield f"http://127.0.0.1:{p}"; srv.shutdown()
@pytest.fixture
def lab_https():
    from cyberswarm.lab import start_https
    p = free_port(); srv = start_https(p); yield f"https://127.0.0.1:{p}"; srv.shutdown()
def T(fs): return [f["check_id"] for f in fs]

def pytest_configure(config):
    config.addinivalue_line('markers','acceptance: critérios de aceitação CyberSwarm 2.0')
