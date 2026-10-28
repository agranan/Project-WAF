
from fastapi import FastAPI

from app.waf import WAFMiddleware
from app.database import init_db
from app.routes import router

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from fastapi import FastAPI, Form, Body
app = FastAPI(
    title="Simple WAF",
    description="A rule-based Web Application Firewall",
    version="0.1.0",
)
from fastapi import Form, HTTPException, Request
from app.auth_protection import (
    is_locked,
    record_failed_login,
    reset_failed_logins,
)
from app.database import log_event

app.add_middleware(WAFMiddleware)
init_db()
app.include_router(router)

@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get("/")
async def home():
    return {"message": "Simple WAF is running"}


@app.get("/products")
async def get_product(id: str = "1"):
    return {
        "message": "Product request successful",
        "product_id": id,
    }

templates = Jinja2Templates(directory="app/templates")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
    )


@app.post("/login")
async def demo_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    source_ip = request.client.host if request.client else "unknown"
    request_id = getattr(request.state, "request_id", "unknown")

    if is_locked(username):
        log_event(
            request_id=request_id,
            source_ip=source_ip,
            method="POST",
            path="/login",
            rule_id="AUTH-001",
            reason="Login blocked due to repeated failed attempts",
            action="BLOCK",
        )
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
        )

    # Demo credentials only
    if username != "demo" or password != "password123":
        locked = record_failed_login(username)

        if locked:
            log_event(
                request_id=request_id,
                source_ip=source_ip,
                method="POST",
                path="/login",
                rule_id="AUTH-001",
                reason="Account locked after repeated failed login attempts",
                action="BLOCK",
            )
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again later.",
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    reset_failed_logins(username)

    return {"message": "Demo login successful", "username": username}


@app.post("/api/search")
async def search_api(payload: dict = Body(...)):
    return {
        "message": "Search request received",
        "query": payload.get("query", ""),
    }