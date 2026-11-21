"""FastAPI entrypoint. Run:  uvicorn app:app --host 0.0.0.0 --port 8000"""
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ai_service import (AnalyzerError, LogAnalyzer, ProviderRejectedError,
                        ProviderUnavailableError)
from config import load_settings
from logger_config import request_id_var, setup_logging

logger = logging.getLogger("app")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class AnalyzeRequest(BaseModel):
    logs: str


class AnalyzeResponse(BaseModel):
    request_id: str
    summary: str
    severity: str
    probable_root_cause: str
    affected_components: List[str]
    recommended_actions: List[str]
    model: str
    attempts: int
    latency_ms: int


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()          # fail fast on missing/invalid config
    setup_logging(settings.log_level)
    app.state.settings = settings
    app.state.analyzer = LogAnalyzer(settings)
    yield
    await app.state.analyzer.aclose()


app = FastAPI(title="AI Log Analyzer", lifespan=lifespan)


def _error(status: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id_var.get()}},
        headers=headers,
    )


@app.middleware("http")
async def request_context(request: Request, call_next):
    incoming = request.headers.get("x-request-id", "")
    rid = incoming if _SAFE_ID.match(incoming) else uuid.uuid4().hex
    token = request_id_var.set(rid)
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = rid
        return response
    except Exception:  # last line of defense: never crash the worker
        logger.exception("unhandled error", extra={"event": "unhandled_error"})
        return _error(500, "internal_error", "Unexpected server error.", {"X-Request-ID": rid})
    finally:
        logger.info("request completed", extra={
            "event": "request", "method": request.method, "path": request.url.path,
            "status": status, "latency_ms": int((time.perf_counter() - start) * 1000)})
        request_id_var.reset(token)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest, request: Request):
    limit = request.app.state.settings.max_log_chars
    if not body.logs.strip():
        return _error(422, "empty_logs", "Field 'logs' must not be empty.")
    if len(body.logs) > limit:
        return _error(413, "logs_too_large", f"Logs exceed the {limit}-character limit.")

    logger.info("analysis requested", extra={"event": "analyze_start", "log_chars": len(body.logs)})
    try:
        result = await request.app.state.analyzer.analyze(body.logs)
    except ProviderUnavailableError as exc:
        status = 504 if exc.reason == "deadline_exceeded" else 503
        logger.warning("provider unavailable", extra={
            "event": "provider_unavailable", "attempt": exc.attempts, "outcome": exc.reason})
        return _error(status, "provider_unavailable",
                      "The AI provider is temporarily unavailable. Please retry shortly.",
                      {"Retry-After": "30"})
    except ProviderRejectedError as exc:
        # Likely our misconfiguration (bad key) or invalid input; don't leak details.
        logger.error("provider rejected request", extra={
            "event": "provider_rejected", "status": exc.status})
        return _error(502, "provider_error", "The AI provider could not process this request.")
    except AnalyzerError:
        return _error(500, "analysis_failed", "Analysis failed.")

    return AnalyzeResponse(request_id=request_id_var.get(), **{
        k: getattr(result, k) for k in AnalyzeResponse.model_fields if k != "request_id"})
