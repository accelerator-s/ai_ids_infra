from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import DATA_DIR, DATABASE_URL


class Base(DeclarativeBase):
    """所有数据库模型的基类，用于统一创建数据表。"""


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """初始化 SQLite 数据库目录和数据表。"""
    from app.database import models  # noqa: F401

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # create_all 不会给既有 SQLite 表补列。这里执行向后兼容的轻量迁移，
    # 让升级前创建的 ids.db 也能保存 AI 研判置信度。
    columns = {column["name"] for column in inspect(engine).get_columns("alerts")}
    if "ai_confidence" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN ai_confidence FLOAT"))


def get_db() -> Generator[Session, None, None]:
    """为 FastAPI 接口提供数据库会话，并在请求结束后自动关闭。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
