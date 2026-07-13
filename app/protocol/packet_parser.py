"""将 PyShark 数据包转换为检测模块使用的 HTTP 请求字典。"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlsplit


def parse_http_request(packet: Any) -> dict[str, Any] | None:
    """解析单个 PyShark 数据包为结构化 HTTP 请求字典。"""
    http = getattr(packet, "http", None)
    ip = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
    tcp = getattr(packet, "tcp", None)
    if http is None or ip is None or tcp is None:
        return None

    method = _text(http, "request_method")
    request_uri = _text(http, "request_uri")
    if not method or not request_uri:
        return None

    uri = urlsplit(request_uri)
    headers = _headers(http)
    timestamp = _timestamp(packet)
    return {
        "src_ip": _text(ip, "src"),
        "dst_ip": _text(ip, "dst"),
        "src_port": _integer(tcp, "srcport"),
        "dst_port": _integer(tcp, "dstport"),
        "protocol": "HTTP",
        "timestamp": timestamp,
        "method": method,
        "host": _text(http, "host"),
        "path": uri.path or request_uri.split("?", 1)[0],
        "query": _text(http, "request_uri_query") or uri.query,
        "headers": headers,
        "body": _text(http, "file_data"),
    }


def _text(layer: Any, field: str) -> str:
    """安全读取协议层文本字段。"""
    value = getattr(layer, field, "")
    return str(value) if value is not None else ""


def _integer(layer: Any, field: str) -> int | None:
    """安全读取协议层端口字段。"""
    try:
        return int(_text(layer, field))
    except (TypeError, ValueError):
        return None


def _headers(http: Any) -> dict[str, str]:
    """提取常用 HTTP 请求头并统一为标准名称。"""
    fields = {
        "host": "Host",
        "user_agent": "User-Agent",
        "content_type": "Content-Type",
        "content_length": "Content-Length",
        "referer": "Referer",
        "cookie": "Cookie",
    }
    return {
        header: value
        for field, header in fields.items()
        if (value := _text(http, field))
    }


def _timestamp(packet: Any) -> str:
    """读取抓包时间并统一为 ISO 8601 字符串。"""
    value = getattr(packet, "sniff_time", None)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or getattr(packet, "sniff_timestamp", ""))
