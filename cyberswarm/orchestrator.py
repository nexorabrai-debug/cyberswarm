"""asyncio orchestrator: task queue, parallel workers, scope gate per task, per-task timeout,
retries with backoff (error recovery), partial results, per-task hook (used by Hacker AI for tool metrics), post-processing."""
import asyncio, time
from dataclasses import dataclass, field
from .registry import load_all
from .scope import OutOfScope
from .agents.validation import validate
@dataclass
class Ctx:
    scope: object; log: object; net: object; audit: object; options: dict = field(default_factory=dict)
class PartialResult(Exception):
    """Raise from an agent to return what it found before failing (partial result is kept, task marked 'partial')."""
    def __init__(self, findings, reason=""):
        super().__init__(reason); self.findings = findings; self.reason = reason
class Orchestrator:
    def __init__(self, ctx, db, workers=4, task_timeout=120, retries=0, backoff=0.2, on_task=None):
        self.ctx, self.db, self.workers, self.timeout = ctx, db, workers, task_timeout
        self.retries, self.backoff, self.on_task = retries, backoff, on_task
        self.agents = load_all()
    async def _attempt(self, name, target):
        return await asyncio.wait_for(self.agents[name](self.ctx).run(target), self.timeout)
    async def _worker(self, q, out):
        while True:
            tid, name, target = await q.get(); t0 = time.monotonic(); status, n, attempts = "error", 0, 0
            try:
                self.ctx.scope.check(target)
                self.ctx.audit.log("task_start", task=tid, agent=name, target=target)
                self.db.update_task(tid, "running")
                while True:
                    attempts += 1
                    try:
                        res = await self._attempt(name, target)
                        for f in res: f.setdefault("task_target", target)
                        out.extend(res); n = len(res); status = "done"; self.db.update_task(tid, "done")
                        self.ctx.audit.log("task_done", task=tid, agent=name, findings=n, attempts=attempts); break
                    except PartialResult as p:
                        for f in p.findings: f.setdefault("task_target", target)
                        out.extend(p.findings); n = len(p.findings); status = "partial"; self.db.update_task(tid, "partial", p.reason)
                        self.ctx.audit.log("task_partial", task=tid, agent=name, findings=n, reason=p.reason[:200]); break
                    except (OutOfScope, PermissionError): raise
                    except Exception as e:
                        if attempts > self.retries: raise
                        self.ctx.audit.log("task_retry", task=tid, agent=name, attempt=attempts, error=repr(e)[:200])
                        await asyncio.sleep(self.backoff * attempts)
            except (OutOfScope, PermissionError) as e:
                status = "rejected"; self.db.update_task(tid, "rejected", str(e)); self.ctx.audit.log("scope_denied", task=tid, agent=name, target=target)
            except Exception as e:
                self.db.update_task(tid, "error", repr(e)); self.ctx.audit.log("task_error", task=tid, agent=name, error=repr(e)[:200], attempts=attempts)
                self.ctx.log.error(f"{name} falhou: {e!r}")
            finally:
                if self.on_task: self.on_task(name, target, status, n, time.monotonic() - t0, attempts)
                q.task_done()
    async def run(self, jobs, label="scan", client=None, rid=None, finalize=True):
        rid = rid or self.db.new_run(label, client); q = asyncio.Queue(); out = []
        self.ctx.audit.log("run_start", run=rid, label=label, client=client, jobs=len(jobs))
        for name, target in jobs: q.put_nowait((self.db.add_task(rid, name, target), name, target))
        ws = [asyncio.create_task(self._worker(q, out)) for _ in range(self.workers)]
        await q.join()
        for w in ws: w.cancel()
        if not finalize: return rid, out
        final = validate(out)
        for f in final: self.db.add_finding(rid, f)
        self.db.finish_run(rid); self.ctx.audit.log("run_done", run=rid, findings=len(final))
        return rid, final
