from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import BASE_DIR
from app.database.db import init_db

app = FastAPI(title="AI-IDS-Infrastructure", version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    """服务启动时初始化 SQLite 数据库。"""
    init_db()


app.include_router(router)

frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
