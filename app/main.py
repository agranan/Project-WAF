
from fastapi import FastAPI

from app.waf import WAFMiddleware

app = FastAPI(
    title="Simple WAF",
    description="A rule-based Web Application Firewall",
    version="0.1.0",
)

app.add_middleware(WAFMiddleware)


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get("/")
async def home():
    return {"message": "Simple WAF is running"}
