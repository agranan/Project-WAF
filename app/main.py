
from fastapi import FastAPI

from app.waf import WAFMiddleware
from app.database import init_db
from app.routes import router

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from fastapi import FastAPI, Form

app = FastAPI(
    title="Simple WAF",
    description="A rule-based Web Application Firewall",
    version="0.1.0",
)

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
    username: str = Form(...),
    password: str = Form(...),
):
    # Demonstration endpoint only; no real authentication.
    return {
        "message": "Demo login request received",
        "username": username,
    }