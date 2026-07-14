"""后端 API 路由。

已可用：状态查询、运行配置、大模型连通、AI 评测报告、任务、告警、
统计、开发辅助。
待实现：实时抓包、pcap 离线分析，相关路由统一返回 501，
具体约定见仓库根目录的 API.md。
"""

from datetime import datetime
from importlib.util import find_spec
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai import report_generator
from app.config import RULES_DIR
from app.database import crud
from app.database.db import get_db
from app.services import llm

router = APIRouter(prefix="/api")

SERVICE_NAME = "ai-ids-infra"
SERVICE_VERSION = "0.1.0"

# 各功能模块对应的实现文件，用于在 /api/status 里汇报就绪情况。
# 模块文件落地后这里会自动检测到，无需修改状态接口。
MODULE_SPECS = {
    "rule_engine": ("app.detection.rule_engine", "规则检测"),
    "risk_score": ("app.detection.risk_score", "风险评分"),
    "behavior_detector": ("app.detection.behavior_detector", "行为检测"),
    "packet_parser": ("app.protocol.packet_parser", "协议解析"),
    "live_capture": ("app.capture.live_capture", "实时抓包"),
    "pcap_analyzer": ("app.capture.pcap_analyzer", "pcap 离线分析"),
    "ai_analyzer": ("app.ai.request_analyzer", "AI 辅助研判"),
    "ai_report": ("app.ai.report_generator", "AI 评测报告"),
}


def module_exists(module_path: str) -> bool:
    """find_spec 在父包不存在时会抛 ModuleNotFoundError，一并按未实现处理。"""
    try:
        return find_spec(module_path) is not None
    except ModuleNotFoundError:
        return False


def not_implemented(module: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=501,
        detail={"code": "not_implemented", "module": module, "message": message},
    )


# ---------- 请求体 ----------


class TaskCreateRequest(BaseModel):
    """创建分析任务，供抓包和 pcap 分析模块落地后复用。"""

    task_type: str = Field(..., examples=["pcap"])
    target: str = Field(default="", examples=["sample_http_attack.pcap"])
    status: str = Field(default="pending", examples=["pending"])


class TaskUpdateRequest(BaseModel):
    status: str | None = None
    packet_count: int | None = None
    http_count: int | None = None
    alert_count: int | None = None
    finished: bool = False


class AlertCreateRequest(BaseModel):
    """写入一条告警，检测链路打通后由检测模块调用。"""

    task_id: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    method: str = ""
    path: str = ""
    query: str = ""
    attack_type: str = "Unknown"
    risk_level: str = "low"
    score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    ai_judgement: str = ""
    ai_reason: str = ""
    reason: str = ""
    status: str = "new"


class ServerConfig(BaseModel):
    port: int | None = Field(default=None, ge=1, le=65535)


class LlmConfig(BaseModel):
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    temperature: float | None = Field(default=None, ge=0, le=2)


class ConfigUpdateRequest(BaseModel):
    server: ServerConfig | None = None
    llm: LlmConfig | None = None


class LlmModelsRequest(BaseModel):
    base_url: str = ""
    api_key: str = ""


class LlmTestRequest(BaseModel):
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = Field(default=0.2, ge=0, le=2)


class CaptureStartRequest(BaseModel):
    interface: str = ""
    target_type: str = Field(default="ip", examples=["ip", "domain"])
    target: str = ""
    port: int = Field(default=80, ge=1, le=65535)


class CaptureStopRequest(BaseModel):
    task_id: int


class ReportGenerateRequest(BaseModel):
    task_id: int


class ResetDatabaseRequest(BaseModel):
    confirm: bool = False


# ---------- 状态与配置 ----------


def _rule_engine_status() -> dict[str, Any]:
    try:
        from app.detection.rule_engine import load_rules

        rules = load_rules(RULES_DIR)
        files = len(list(RULES_DIR.glob("*.json")))
        return {"ready": True, "rule_count": len(rules), "rule_files": files}
    except Exception as exc:
        return {"ready": False, "reason": f"规则库加载失败：{exc}"}


def _database_status(db: Session) -> dict[str, Any]:
    try:
        db.execute(text("SELECT 1"))
        return {"ready": True}
    except Exception as exc:
        return {"ready": False, "reason": str(exc)}


def _public_llm_config(settings: dict[str, Any]) -> dict[str, Any]:
    return {
        "base_url": settings["llm.base_url"],
        "model": settings["llm.model"],
        "temperature": settings["llm.temperature"],
        "has_api_key": bool(settings["llm.api_key"]),
    }


@router.get("/status")
def get_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    """返回服务信息、各模块就绪情况和大模型配置摘要，供 WebUI 健康检查。"""
    modules: dict[str, Any] = {"database": _database_status(db)}
    for name, (module_path, label) in MODULE_SPECS.items():
        if name == "rule_engine":
            modules[name] = _rule_engine_status()
        elif module_exists(module_path):
            modules[name] = {"ready": True}
        else:
            modules[name] = {"ready": False, "reason": f"{label}模块尚未实现"}

    settings = crud.get_settings(db)
    return {
        "status": "ok",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "server": {"configured_port": settings["server.port"]},
        "modules": modules,
        "llm": _public_llm_config(settings),
    }


@router.get("/config")
def get_config(db: Session = Depends(get_db)) -> dict[str, Any]:
    """返回运行配置，访问密钥只回传是否已保存。"""
    settings = crud.get_settings(db)
    return {
        "server": {"port": settings["server.port"]},
        "llm": _public_llm_config(settings),
    }


@router.post("/config")
def save_config(request: ConfigUpdateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """保存运行配置。api_key 传空或缺省时保留已存的密钥，端口修改重启后生效。"""
    values: dict[str, Any] = {}
    if request.server is not None and request.server.port is not None:
        values["server.port"] = request.server.port
    if request.llm is not None:
        cfg = request.llm
        if cfg.base_url is not None:
            values["llm.base_url"] = cfg.base_url.strip().rstrip("/")
        if cfg.api_key:
            values["llm.api_key"] = cfg.api_key.strip()
        if cfg.model is not None:
            values["llm.model"] = cfg.model.strip()
        if cfg.temperature is not None:
            values["llm.temperature"] = cfg.temperature

    settings = crud.save_settings(db, values)
    return {
        "server": {"port": settings["server.port"]},
        "llm": _public_llm_config(settings),
    }


def _resolve_llm_credentials(
    db: Session, base_url: str, api_key: str
) -> tuple[str, str]:
    """请求里没带密钥且服务地址与已保存配置一致时，回落到已保存的密钥。"""
    settings = crud.get_settings(db)
    base = base_url.strip().rstrip("/") or settings["llm.base_url"]
    key = api_key.strip()
    if not key and base == settings["llm.base_url"]:
        key = settings["llm.api_key"]
    if not base:
        raise HTTPException(status_code=400, detail="请先填写服务地址")
    if not key:
        raise HTTPException(status_code=400, detail="请先填写访问密钥")
    return base, key


@router.post("/llm/models")
def list_llm_models(request: LlmModelsRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """按 OpenAI 兼容协议拉取模型列表。"""
    base, key = _resolve_llm_credentials(db, request.base_url, request.api_key)
    try:
        models = llm.fetch_models(base, key)
    except llm.LlmError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"models": models}


@router.post("/llm/test")
def test_llm(request: LlmTestRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """向所选模型发送一条测试消息，返回回复内容和耗时。"""
    base, key = _resolve_llm_credentials(db, request.base_url, request.api_key)
    settings = crud.get_settings(db)
    model = request.model.strip() or settings["llm.model"]
    if not model:
        raise HTTPException(status_code=400, detail="请先选择模型")
    try:
        result = llm.chat_once(
            base_url=base,
            api_key=key,
            model=model,
            system="你是网络入侵检测系统的测试助手。",
            user="收到请回复一句话，说明你是什么模型。",
            temperature=request.temperature,
        )
    except llm.LlmError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return result


# ---------- 实时抓包（待实现） ----------


@router.get("/capture/interfaces")
def list_interfaces() -> dict[str, Any]:
    raise not_implemented("live_capture", "实时抓包模块尚未实现，暂时无法列出网卡")


@router.post("/capture/start")
def start_capture(request: CaptureStartRequest) -> dict[str, Any]:
    raise not_implemented("live_capture", "实时抓包模块尚未实现，暂时无法启动抓包任务")


@router.post("/capture/stop")
def stop_capture(request: CaptureStopRequest) -> dict[str, Any]:
    raise not_implemented("live_capture", "实时抓包模块尚未实现，暂时无法停止抓包任务")


# ---------- pcap 离线分析（待实现） ----------


@router.post("/pcap/analyze")
def analyze_pcap() -> dict[str, Any]:
    raise not_implemented("pcap_analyzer", "pcap 离线分析模块尚未实现，暂时无法解析流量包")


# ---------- AI 评测报告 ----------


@router.get("/reports")
def list_reports(
    task_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    reports = crud.list_reports(db, task_id=task_id, limit=limit, offset=offset)
    return {"items": [crud.report_to_dict(report) for report in reports]}


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    report = crud.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return crud.report_to_dict(report)


@router.post("/reports/generate")
def generate_report(request: ReportGenerateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """对指定任务生成评测报告，生成失败时保存 failed 记录并返回 502。"""
    task = crud.get_task(db, request.task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    settings = crud.get_settings(db)
    if not (settings["llm.base_url"] and settings["llm.api_key"] and settings["llm.model"]):
        raise HTTPException(
            status_code=400,
            detail="请先在系统配置页填写大模型服务地址、访问密钥和模型",
        )

    report = report_generator.generate(db, task, settings)
    if report.status == "failed":
        raise HTTPException(status_code=502, detail=report.error_message)
    return crud.report_to_dict(report)


# ---------- 任务 ----------


@router.post("/tasks")
def create_task(request: TaskCreateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = crud.create_task(
        db,
        task_type=request.task_type,
        target=request.target,
        status=request.status,
    )
    return crud.task_to_dict(task)


@router.get("/tasks")
def list_tasks(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    tasks = crud.list_tasks(db, limit=limit, offset=offset)
    return {"items": [crud.task_to_dict(task) for task in tasks]}


@router.patch("/tasks/{task_id}")
def update_task(
    task_id: int,
    request: TaskUpdateRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    task = crud.update_task(
        db,
        task_id,
        status=request.status,
        packet_count=request.packet_count,
        http_count=request.http_count,
        alert_count=request.alert_count,
        finished_at=datetime.utcnow() if request.finished else None,
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return crud.task_to_dict(task)


# ---------- 告警 ----------


@router.post("/alerts")
def create_alert(request: AlertCreateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    alert = crud.create_alert(db, **request.model_dump())
    if alert is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return crud.alert_to_dict(alert)


@router.get("/alerts")
def list_alerts(
    attack_type: str | None = None,
    risk_level: str | None = None,
    src_ip: str | None = None,
    task_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    alerts = crud.list_alerts(
        db,
        attack_type=attack_type,
        risk_level=risk_level,
        src_ip=src_ip,
        task_id=task_id,
        limit=limit,
        offset=offset,
    )
    return {"items": [crud.alert_to_dict(alert) for alert in alerts]}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    alert = crud.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return crud.alert_to_dict(alert)


# ---------- 统计 ----------


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
    return crud.get_stats(db)


# ---------- 开发辅助 ----------


@router.post("/dev/reset-database")
def reset_database(request: ResetDatabaseRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """清空任务和告警数据，保留表结构和运行配置。"""
    if not request.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")

    result = crud.reset_database(db)
    return {"status": "reset", **result}
