
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        request.state.request_id = request_id

        response = await call_next(request)

        duration_ms = round(
            (time.perf_counter() - start_time) * 1000, 2
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-MS"] = str(duration_ms)

        return response
