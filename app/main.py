
from fastapi import FastAPI

from app.waf import WAFMiddleware
from app.database import init_db
from app.routes import router

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
