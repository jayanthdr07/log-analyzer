# AI Log Analyzer

A small, resilient Python service that accepts server logs and returns an AI-generated incident analysis (summary, severity, probable root cause, affected components, recommended actions).

Built with FastAPI and httpx, calling the Anthropic Messages API. The focus is reliability: bounded retries, strict time limits, controlled errors, and no sensitive data in logs.

## Project structure

```
ai-log-analyzer/
├── app.py               # FastAPI app, request-ID middleware, error mapping
├── ai_service.py        # LLM client, failure classification, response parsing
├── retry_handler.py     # Bounded exponential backoff + full jitter + deadline
├── config.py            # Settings from environment; Secret wrapper for the API key
├── logger_config.py     # JSON logging, request-ID correlation, secret redaction
├── tests/
│   └── test_resilience.py
├── requirements.txt
├── .env                 # Local secrets (git-ignored)
├── .env.example         # Template safe to commit
└── .gitignore
```

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Add your key to .env
#   ANTHROPIC_API_KEY=your-key-here

uvicorn app:app --host 0.0.0.0 --port 8000
```

The service refuses to start if `ANTHROPIC_API_KEY` is missing or still set to the `replace-me` placeholder.

## API

### `POST /analyze`

Request:

```bash
curl -X POST http://localhost:8000/analyze \
  -H 'content-type: application/json' \
  -H 'x-request-id: my-trace-id-123' \
  -d '{"logs": "2026-11-21 10:02:11 ERROR db pool exhausted\n2026-11-21 10:02:12 WARN request timeout /checkout"}'
```

Response `200`:

```json
{
  "request_id": "my-trace-id-123",
  "summary": "The database connection pool was exhausted, causing checkout requests to time out.",
  "severity": "high",
  "probable_root_cause": "Connection pool saturation under load.",
  "affected_components": ["database", "checkout"],
  "recommended_actions": ["Increase pool size", "Check for leaked connections"],
  "model": "claude-sonnet-5-5",
  "attempts": 1,
  "latency_ms": 2140
}
```

`x-request-id` is optional. If it is missing or not 8 to 64 characters of `[A-Za-z0-9._-]`, a new ID is generated. The ID is always returned in the `X-Request-ID` header and in logs.

### `GET /health`

Returns `{"status": "ok"}`. It does not call the provider.

### Error responses

All errors share one shape:

```json
{"error": {"code": "provider_unavailable", "message": "...", "request_id": "..."}}
```

| Status | Code | Meaning |
|---|---|---|
| 413 | `logs_too_large` | Input exceeds `MAX_LOG_CHARS` |
| 422 | `empty_logs` | `logs` is blank (malformed JSON also returns 422) |
| 502 | `provider_error` | Provider rejected the request (e.g. invalid key, bad request). Retrying will not help. |
| 503 | `provider_unavailable` | Transient failures persisted after all retries. Includes `Retry-After`. |
| 504 | `provider_unavailable` | Overall time limit exceeded. Includes `Retry-After`. |
| 500 | `internal_error` | Unexpected error. The process keeps serving. |

## Configuration

Set via environment variables or `.env`.

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required) | Provider API key |
| `LLM_MODEL` | `claude-sonnet-5-5` | Model name |
| `LLM_MAX_ATTEMPTS` | `4` | Total attempts (1 initial + 3 retries) |
| `LLM_READ_TIMEOUT_S` | `30` | Per-attempt read timeout |
| `LLM_TOTAL_TIMEOUT_S` | `45` | Hard limit across all attempts and backoff sleeps |
| `MAX_LOG_CHARS` | `100000` | Maximum accepted input size |
| `MAX_CONCURRENCY` | `8` | Max simultaneous provider calls per process |
| `LOG_LEVEL` | `INFO` | Logging level |

Other values (connect, write and pool timeouts, backoff base and cap) are defaults in `config.py`.

## Reliability design

**Retries**
- Retried: timeouts, network errors, malformed 200 bodies, and HTTP 408, 409, 429, 500, 502, 503, 504, 529.
- Not retried: 400, 401, 403, 404, 413, 422 and other client errors. These fail immediately.
- Backoff is full jitter: `uniform(0, min(cap, base * 2^(attempt-1)))`. A `Retry-After` header is honored but still capped.
- Retries are bounded twice: by `LLM_MAX_ATTEMPTS` and by `LLM_TOTAL_TIMEOUT_S`. If the next sleep would exceed the remaining budget, the service stops instead of waiting.

**Timeouts**
- httpx enforces connect, read, write and pool timeouts on every attempt.
- Each attempt is also wrapped in `asyncio.wait_for` with the remaining overall budget, so a hanging provider cannot exceed the total limit.

**Failure isolation**
- Provider errors are converted to controlled HTTP responses, never unhandled exceptions.
- A catch-all middleware returns a 500 for unexpected bugs without crashing the worker.
- A semaphore caps concurrent provider calls to avoid overloading the provider or the process.

## Security and privacy

- **API key:** read only from the environment. It is wrapped in a `Secret` object that prints as `***`. It is never logged and never returned in responses. `.env` is git-ignored. In production, inject the key from a secret manager.
- **Logs contain metadata only:** request ID, method, path, status, latency, attempt number and outcome. Request bodies, log text, headers and response bodies are never logged. Exceptions log their type only.
- **Redaction:** log lines and the text sent to the LLM are scrubbed for bearer tokens, JWTs, API keys, AWS keys, private keys, emails, long digit sequences (card-like numbers) and `password=`/`token=`-style pairs. This is regex-based defense in depth, not a guarantee. Review it against your own log formats.
- **Prompt injection:** logs are wrapped in `<logs>` tags and the system prompt instructs the model to treat them as untrusted data. Output is parsed as JSON and validated (severity is restricted to a known set, lists are capped).
- **Error messages:** client-facing errors are generic and do not expose provider responses or internals.

## Example log line

Each provider attempt and each request produces structured output like:

```json
{"ts": "...", "level": "INFO", "logger": "ai_service", "request_id": "my-trace-id-123", "message": "provider call finished", "event": "provider_call", "status": 200, "latency_ms": 2101, "attempt": 1, "outcome": "ok", "model": "claude-sonnet-5-5"}
```

## Testing

```bash
python -m tests.test_resilience
```

These tests use a mocked HTTP transport (no network, no API key needed) and verify:
- Transient 503s are retried, then succeed
- A 401 is not retried (exactly one call)
- Retries stop at `max_attempts`
- Timeouts are retried and bounded
- The total deadline holds against a hanging provider
- Redaction works and the API key never appears in `repr`

## Production notes

- **Multiple workers:** the concurrency limit is per process. Add a gateway or shared rate limiter if you run several workers or replicas.
- **Authentication:** this service has no inbound auth. Put it behind your API gateway or add an auth dependency before exposing it.
- **Large logs:** inputs over `MAX_LOG_CHARS` are rejected rather than truncated. Pre-filter or chunk upstream if you need to analyze more.
- **Data handling:** log text is sent to a third-party provider (after redaction). Confirm this meets your data-handling policy.
- **Monitoring:** alert on 5xx rates and on `retry_scheduled` events, which signal provider instability.
