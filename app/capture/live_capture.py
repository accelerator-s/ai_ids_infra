"""实时 HTTP 明文流量采集、关联和检测。"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
import threading
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pyshark
from sqlalchemy.orm import Session

from app.ai import request_analyzer
from app.config import RULES_DIR
from app.database import crud
from app.database.db import SessionLocal
from app.detection.behavior_detector import BehaviorDetector, BehaviorMatch
from app.detection.risk_score import calculate_risk
from app.detection.rule_engine import RuleEngine
from app.protocol.packet_parser import (
    get_tcp_stream_id,
    parse_http_request,
    parse_http_response_status,
)


logger = logging.getLogger(__name__)
PacketParser = Callable[[Any], dict[str, Any] | None]
SessionFactory = Callable[[], Session]
AiAnalyzer = Callable[[dict[str, Any], Any, dict[str, Any]], request_analyzer.AnalysisResult]


class CaptureConfigurationError(ValueError):
    """抓包输入或目标解析无效。"""


class InterfaceDiscoveryError(RuntimeError):
    """tshark 网卡发现失败。"""


def list_tshark_interfaces(timeout: float = 5.0) -> list[dict[str, str]]:
    """通过 tshark -D 返回稳定的网卡名称和描述。"""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except FileNotFoundError as exc:
        raise InterfaceDiscoveryError("tshark is not installed or not in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise InterfaceDiscoveryError("tshark interface discovery timed out") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        message = "tshark interface discovery failed"
        raise InterfaceDiscoveryError(f"{message}: {detail}" if detail else message) from exc
    except OSError as exc:
        raise InterfaceDiscoveryError(f"unable to run tshark: {exc}") from exc

    interfaces: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        entry = line.strip()
        if not entry or ". " not in entry:
            continue
        _, value = entry.split(". ", 1)
        name, separator, description = value.partition(" ")
        interfaces.append({"name": name, "description": description.strip() if separator else ""})

    if not interfaces:
        raise InterfaceDiscoveryError("tshark reported no capture interfaces")
    return interfaces


def resolve_target(target_type: str, target: str) -> list[str]:
    """校验 IP 或解析域名，并返回排序去重后的地址。"""
    value = target.strip()
    if not value:
        raise CaptureConfigurationError("target is required")
    if target_type == "ip":
        try:
            return [str(ipaddress.ip_address(value))]
        except ValueError as exc:
            raise CaptureConfigurationError("target must be a valid IP address") from exc
    if target_type != "domain":
        raise CaptureConfigurationError("target_type must be 'ip' or 'domain'")

    try:
        records = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise CaptureConfigurationError(f"unable to resolve domain: {value}") from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _socktype, _proto, _canonname, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            continue
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
        except (ValueError, IndexError):
            continue
    if not addresses:
        raise CaptureConfigurationError(f"domain resolved to no IP addresses: {value}")
    return [str(address) for address in sorted(addresses, key=lambda item: (item.version, int(item)))]


def build_capture_filter(addresses: Iterable[str], port: int) -> str:
    """用已验证地址和端口构造 BPF 过滤表达式。"""
    if not 1 <= port <= 65535:
        raise CaptureConfigurationError("port must be between 1 and 65535")
    normalized = [str(ipaddress.ip_address(address)) for address in addresses]
    unique = list(dict.fromkeys(normalized))
    if not unique:
        raise CaptureConfigurationError("at least one target IP address is required")
    hosts = [f"host {address}" for address in unique]
    if len(hosts) == 1:
        return f"{hosts[0]} and tcp port {port}"
    return f"({' or '.join(hosts)}) and tcp port {port}"


@dataclass
class LiveCaptureSession:
    """单个实时抓包任务的线程、检测状态和资源。"""

    task_id: int
    interface: str
    target: str
    capture_filter: str
    session_factory: SessionFactory = SessionLocal
    packet_parser: PacketParser = parse_http_request
    rule_engine: RuleEngine | None = None
    ai_analyzer: AiAnalyzer = request_analyzer.analyze
    settings: dict[str, Any] | None = None
    behavior_detector: BehaviorDetector = field(default_factory=BehaviorDetector)
    capture_factory: Callable[..., Any] = pyshark.LiveCapture
    on_finished: Callable[["LiveCaptureSession"], None] | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    capture: Any | None = field(default=None, init=False)
    thread: threading.Thread | None = field(default=None, init=False)
    _capture_lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _stop_lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _packet_count: int = field(default=0, init=False)
    _http_count: int = field(default=0, init=False)
    _alert_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.rule_engine is None:
            self.rule_engine = RuleEngine.from_dir(RULES_DIR)

    def start(self) -> None:
        """启动本任务的后台抓包线程。"""
        self.thread = threading.Thread(target=self.run, name=f"live-capture-{self.task_id}", daemon=True)
        self.thread.start()

    def request_stop(self) -> bool:
        """请求停止抓包，并关闭 capture 以解除读取阻塞。"""
        with self._stop_lock:
            if self.stop_event.is_set():
                return False
            self.stop_event.set()
        self._close_capture()
        return True

    def run(self) -> None:
        """在线程中抓包、关联 HTTP 请求响应并写入检测结果。"""
        db: Session | None = None
        pending: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
        status = "completed"
        try:
            db = self.session_factory()
            if self.settings is None:
                self.settings = crud.get_settings(db)
            self.capture = self.capture_factory(interface=self.interface, bpf_filter=self.capture_filter)
            if not self.stop_event.is_set():
                for packet in self.capture.sniff_continuously():
                    if self.stop_event.is_set():
                        break
                    self._packet_count += 1
                    try:
                        request = self.packet_parser(packet)
                        response_status = parse_http_response_status(packet)
                        stream_id = get_tcp_stream_id(packet)
                    except Exception as exc:
                        logger.warning("Skipping live packet %d after parsing error: %s", self._packet_count, exc)
                        continue

                    if request is not None:
                        self._http_count += 1
                        if stream_id is not None:
                            pending[stream_id].append(request)
                            self._persist_counts(db)
                        else:
                            self._process_request(db, request)
                        continue
                    if response_status is not None and stream_id is not None:
                        waiting = pending.get(stream_id)
                        if waiting:
                            request = waiting.popleft()
                            request["status"] = response_status
                            self._process_request(db, request)
                            if not waiting:
                                pending.pop(stream_id, None)
                    self._persist_counts(db)
        except Exception as exc:
            status = "failed"
            logger.exception("Live capture task %d failed: %s", self.task_id, exc)
            if db is not None:
                db.rollback()
        finally:
            if db is not None:
                try:
                    for requests in pending.values():
                        while requests:
                            self._process_request(db, requests.popleft())
                    self._persist_counts(db, status=status, finished=True)
                except Exception as exc:
                    status = "failed"
                    logger.exception("Failed to finalize live capture task %d: %s", self.task_id, exc)
                    db.rollback()
                    try:
                        self._persist_counts(db, status=status, finished=True)
                    except Exception:
                        db.rollback()
                finally:
                    db.close()
            self._close_capture()
            if self.on_finished is not None:
                self.on_finished(self)

    def _process_request(self, db: Session, request: dict[str, Any]) -> None:
        """对已完成关联的 HTTP 请求执行规则和行为检测。"""
        assert self.rule_engine is not None
        matches = self.rule_engine.match(request)
        risk = calculate_risk(matches)
        if risk.level == "normal":
            pass
        elif risk.need_ai_filter:
            self._alert_count += self._review_ambiguous_request(db, request, risk)
        else:
            self._alert_count += int(self._create_rule_alert(db, request, risk) is not None)
        for match in self.behavior_detector.detect([request]):
            self._alert_count += self._create_behavior_alert(db, match)
        self._persist_counts(db)

    def _review_ambiguous_request(self, db: Session, request: dict[str, Any], risk: Any) -> int:
        """研判模糊规则风险，并保存 AI 结果或待人工复核记录。"""
        matched_rules = [match.rule_id for match in risk.matches]
        summary = request_analyzer.request_summary(request)
        settings = self.settings or {}
        try:
            result = self.ai_analyzer(request, risk, settings)
        except Exception as exc:
            logger.warning("AI review failed for live task %s: %s", self.task_id, exc)
            crud.create_ai_review(
                db,
                task_id=self.task_id,
                request_summary=summary,
                original_score=risk.score,
                matched_rules=matched_rules,
                judgement="manual_review",
                attack_type=self._attack_types(risk),
                reason=str(exc),
                status="pending_review",
                model=str(settings.get("llm.model", "")),
                prompt_version=request_analyzer.PROMPT_VERSION,
            )
            return 0

        alert = None
        if result.ai_judgement == "malicious":
            alert = self._create_rule_alert(
                db,
                request,
                risk,
                attack_type=result.attack_type,
                ai_judgement=result.ai_judgement,
                ai_confidence=result.confidence,
                ai_reason=result.reason,
            )
        crud.create_ai_review(
            db,
            task_id=self.task_id,
            alert_id=alert.id if alert is not None else None,
            request_summary=summary,
            original_score=risk.score,
            matched_rules=matched_rules,
            judgement=result.ai_judgement,
            attack_type=result.attack_type,
            confidence=result.confidence,
            reason=result.reason,
            status="completed",
            model=result.model,
            prompt_version=result.prompt_version,
        )
        return int(alert is not None)

    def _create_rule_alert(
        self,
        db: Session,
        request: dict[str, Any],
        risk: Any,
        *,
        attack_type: str | None = None,
        ai_judgement: str = "",
        ai_confidence: float | None = None,
        ai_reason: str = "",
    ) -> Any:
        """写入规则评分及可选 AI 结论告警。"""
        return crud.create_alert(
            db,
            task_id=self.task_id,
            src_ip=str(request.get("src_ip", "")),
            dst_ip=str(request.get("dst_ip", "")),
            src_port=request.get("src_port"),
            dst_port=request.get("dst_port"),
            method=str(request.get("method", "")),
            path=str(request.get("path", "")),
            query=str(request.get("query", "")),
            attack_type=attack_type or self._attack_types(risk),
            risk_level=risk.level,
            score=risk.score,
            matched_rules=[item.rule_id for item in risk.matches],
            ai_judgement=ai_judgement,
            ai_confidence=ai_confidence,
            ai_reason=ai_reason,
            reason="；".join(item.reason for item in risk.matches),
        )

    @staticmethod
    def _attack_types(risk: Any) -> str:
        """汇总规则命中的攻击类型。"""
        return ", ".join(sorted({match.attack_type for match in risk.matches})) or "Unknown"

    def _create_behavior_alert(self, db: Session, match: BehaviorMatch) -> int:
        """写入实时行为检测产生的告警。"""
        alert = crud.create_alert(
            db,
            task_id=self.task_id,
            src_ip=match.src_ip,
            attack_type=match.attack_type,
            risk_level=match.level,
            score=match.score,
            matched_rules=[],
            reason=match.reason,
        )
        return int(alert is not None)

    def _persist_counts(self, db: Session, *, status: str = "running", finished: bool = False) -> None:
        """持久化当前统计及可选的最终任务状态。"""
        crud.update_task(
            db,
            self.task_id,
            status=status,
            packet_count=self._packet_count,
            http_count=self._http_count,
            alert_count=self._alert_count,
            finished_at=datetime.utcnow() if finished else None,
        )

    def _close_capture(self) -> None:
        """关闭当前 capture，关闭错误不影响资源清理。"""
        with self._capture_lock:
            capture, self.capture = self.capture, None
        if capture is not None:
            try:
                capture.close()
            except Exception as exc:
                logger.debug("Unable to close live capture task %d: %s", self.task_id, exc)


class LiveCaptureManager:
    """管理进程内所有实时抓包任务。"""

    def __init__(
        self,
        session_factory: SessionFactory = SessionLocal,
        session_class: type[LiveCaptureSession] = LiveCaptureSession,
    ) -> None:
        self.session_factory = session_factory
        self.session_class = session_class
        self._sessions: dict[int, LiveCaptureSession] = {}
        self._lock = threading.Lock()

    def start(self, db: Session, *, interface: str, target_type: str, target: str, port: int) -> Any:
        """创建实时抓包任务并立即启动其后台线程。"""
        if not interface.strip():
            raise CaptureConfigurationError("interface is required")
        addresses = resolve_target(target_type, target)
        capture_filter = build_capture_filter(addresses, port)
        task = crud.create_task(db, task_type="live", target=target.strip(), status="running")
        try:
            session = self.session_class(
                task_id=task.id,
                interface=interface.strip(),
                target=target.strip(),
                capture_filter=capture_filter,
                session_factory=self.session_factory,
                on_finished=self._remove,
            )
            with self._lock:
                self._sessions[task.id] = session
            session.start()
        except Exception:
            with self._lock:
                self._sessions.pop(task.id, None)
            crud.update_task(db, task.id, status="failed", finished_at=datetime.utcnow())
            raise
        return task

    def stop(self, task_id: int) -> bool | None:
        """停止活动任务；None 表示不存在，False 表示已请求停止。"""
        with self._lock:
            session = self._sessions.get(task_id)
        if session is None:
            return None
        return session.request_stop()

    def _remove(self, session: LiveCaptureSession) -> None:
        """在线程结束后移除对应的活动 session。"""
        with self._lock:
            if self._sessions.get(session.task_id) is session:
                self._sessions.pop(session.task_id, None)
