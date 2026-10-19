
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.detectors import detect_sql_injection
from app.database import log_event

class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        request.state.request_id = request_id

        for key, value in request.query_params.multi_items():
            if detect_sql_injection(value):
                log_event(
                    request_id=request_id,
                    source_ip=request.client.host if request.client else "unknown",
                    method=request.method,
                    path=request.url.path,
                    rule_id="SQLI-001",
                    reason="Suspicious SQL injection pattern",
                    action="BLOCK",
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by WAF",
                        "reason": "Suspicious SQL injection pattern",
                        "request_id": request_id,
                    },
                    headers={"X-Request-ID": request_id},
                )

        response = await call_next(request)

        duration_ms = round(
            (time.perf_counter() - start_time) * 1000, 2
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = str(duration_ms)

        return response
