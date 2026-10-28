import time
import uuid
from urllib.parse import parse_qs

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.detectors import (
    detect_sql_injection,
    detect_xss,
    detect_path_traversal,
)
from app.database import log_event
from app.rate_limiter import is_rate_limited

import json

def extract_strings(value):
    """Extract string values from nested JSON objects and arrays."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from extract_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from extract_strings(item)

class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()
        request.state.request_id = request_id

        def block(rule_id: str, reason: str, status_code: int = 403):
            log_event(
                request_id=request_id,
                source_ip=(
                    request.client.host if request.client else "unknown"
                ),
                method=request.method,
                path=request.url.path,
                rule_id=rule_id,
                reason=reason,
                action="BLOCK",
            )

            return JSONResponse(
                status_code=status_code,
                content={
                    "error": "Request blocked by WAF",
                    "reason": reason,
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )

        raw_path = request.scope.get("raw_path", b"").decode(
            "latin-1"
        )

        if detect_path_traversal(request.url.path) or detect_path_traversal(raw_path):
            return block(
                "PATH-001",
                "Path traversal pattern detected",
                status_code=403,
            )

        if is_rate_limited(request):
            return block(
                "RATE-001",
                "Request rate limit exceeded",
                status_code=429,
            )

        # Inspect query parameters.
        for _, value in request.query_params.multi_items():
            if detect_sql_injection(value):
                return block(
                    "SQLI-001",
                    "Suspicious SQL injection pattern",
                )

            if detect_xss(value):
                return block("XSS-001", "Suspicious XSS pattern")

            if detect_path_traversal(value):
                return block(
                    "PATH-001",
                    "Path traversal pattern detected",
                    status_code=403,
                )

        # Inspect URL-encoded form bodies.
        content_type = request.headers.get("content-type", "").lower()

        # Form parameters check
        if (
            request.method in {"POST", "PUT", "PATCH"}
            and content_type.startswith(
                "application/x-www-form-urlencoded"
            )
        ):
            body = await request.body()

            # Avoid parsing excessively large bodies
            if len(body) > 1_000_000:
                return block(
                    "BODY-001",
                    "Request body exceeds inspection limit",
                    status_code=413,
                )

            form_fields = parse_qs(
                body.decode("utf-8", errors="replace"),
                keep_blank_values=True,
            )

            for values in form_fields.values():
                for value in values:
                    if detect_sql_injection(value):
                        return block(
                            "SQLI-001",
                            "Suspicious SQL injection pattern in form body",
                        )

                    if detect_xss(value):
                        return block(
                            "XSS-001",
                            "Suspicious XSS pattern in form body",
                        )

                    if detect_path_traversal(value):
                        return block(
                            "PATH-001",
                            "Path traversal pattern detected",
                            status_code=403,
                        )
        # Inspect JSON bodies
        if (
            request.method in {"POST", "PUT", "PATCH"}
            and content_type.startswith("application/json")
        ):
            body = await request.body()

            if len(body) > 1_000_00:
                return block(
                    "BODY-001",
                    "Request body exceeds inspection limit",
                    status_code=413,
                )

            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return block(
                    "BODY-002",
                    "Malformed JSON request body",
                    status_code=400,
                )

            for value in extract_strings(payload):
                if detect_sql_injection(value):
                    return block(
                        "SQLI-001",
                        "Suspicious SQL injection pattern in JSON body",
                    )

                if detect_xss(value):
                    return block(
                        "XSS-001",
                        "Suspicious XSS pattern in JSON body",
                    )

                if detect_path_traversal(value):
                    return block(
                        "PATH-001",
                        "Path traversal pattern detected",
                        status_code=403,
                    )

        response = await call_next(request)

        duration_ms = round(
            (time.perf_counter() - start_time) * 1000, 2
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = str(duration_ms)

        return response