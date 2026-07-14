"""服务入口。

启动方式：
    python -m app.main [--host 127.0.0.1] [--port 8000]

不带 --port 时使用 WebUI 配置面板里保存的端口（默认 8000）。
"""

import argparse
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import BASE_DIR
from app.database.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI-IDS-Infrastructure", version="0.1.0", lifespan=lifespan)
app.include_router(router)

frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")


def configured_port() -> int:
    """读取 WebUI 面板保存的服务端口。"""
    from app.database import crud
    from app.database.db import SessionLocal

    init_db()
    db = SessionLocal()
    try:
        return int(crud.get_settings(db)["server.port"])
    finally:
        db.close()


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="AI-IDS-Infrastructure WebUI 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None, help="缺省时使用配置面板中保存的端口")
    args = parser.parse_args()

    port = args.port if args.port is not None else configured_port()
    print(f"WebUI 已启动：http://{args.host}:{port}")
    uvicorn.run(app, host=args.host, port=port, log_level="info")


if __name__ == "__main__":
    main()
