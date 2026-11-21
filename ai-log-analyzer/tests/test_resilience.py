"""Run: python -m tests.test_resilience   (no pytest needed)"""
import asyncio, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
from ai_service import LogAnalyzer, ProviderRejectedError, ProviderUnavailableError
from config import Secret, Settings
from logger_config import redact_sensitive

FAST = dict(backoff_base_s=0.01, backoff_max_s=0.05, total_timeout_s=3.0, read_timeout_s=0.2)
OK = {"content": [{"type": "text", "text": '{"summary":"DB pool exhausted","severity":"high"}'}]}


def analyzer(handler, **kw):
    s = Settings(api_key=Secret("sk-test-key-not-real"), **{**FAST, **kw})
    return LogAnalyzer(s, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def main():
    # 1. Transient 503s then success -> retried, succeeds
    calls = []
    def h(req):
        calls.append(1)
        return httpx.Response(503) if len(calls) < 3 else httpx.Response(200, json=OK)
    r = await analyzer(h).analyze("ERROR db timeout")
    assert r.attempts == 3 and r.severity == "high", r
    print("ok: retries transient 503 then succeeds")

    # 2. 401 -> no retry
    calls.clear()
    def h(req): calls.append(1); return httpx.Response(401)
    try: await analyzer(h).analyze("x"); assert False
    except ProviderRejectedError: pass
    assert len(calls) == 1
    print("ok: 401 not retried")

    # 3. Permanent 503 -> bounded attempts, controlled error
    calls.clear()
    def h(req): calls.append(1); return httpx.Response(503)
    try: await analyzer(h, max_attempts=3).analyze("x"); assert False
    except ProviderUnavailableError as e: assert e.reason == "retries_exhausted"
    assert len(calls) == 3
    print("ok: retries bounded at max_attempts")

    # 4. Network timeout -> retried then controlled error
    calls.clear()
    def h(req): calls.append(1); raise httpx.ReadTimeout("slow")
    try: await analyzer(h, max_attempts=2).analyze("x"); assert False
    except ProviderUnavailableError: pass
    assert len(calls) == 2
    print("ok: timeouts retried and bounded")

    # 5. Overall deadline enforced against a hanging provider
    async def hang(req): await asyncio.sleep(10)
    a = analyzer(hang, total_timeout_s=0.5, read_timeout_s=5.0)
    try: await a.analyze("x"); assert False
    except ProviderUnavailableError as e: assert e.reason == "deadline_exceeded"
    print("ok: total deadline enforced")

    # 6. Redaction
    out = redact_sensitive("user=bob@x.com password=hunter2 Authorization: Bearer abc.def.ghi")
    assert "hunter2" not in out and "bob@x.com" not in out and "abc.def" not in out, out
    assert "sk-test" not in repr(Settings(api_key=Secret("sk-test-key-not-real")))
    print("ok: redaction + secret masking")

asyncio.run(main())
