"""将 PyShark 数据包转换为检测模块使用的 HTTP 请求字典。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypedDict
from urllib.parse import parse_qsl, urlsplit


class HttpRequest(TypedDict):
    """规则与行为检测模块共用的结构化 HTTP 请求字段。"""

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    timestamp: str
    method: str
    host: str
    path: str
    query: str
    query_params: dict[str, list[str]]
    headers: dict[str, str]
    user_agent: str
    body: str
    status: int


# 仅映射 PyShark 明确公开的 HTTP 首部字段，避免混入重组、请求行等协议元数据。
_HEADER_FIELDS = {
    "host": "Host",
    "user_agent": "User-Agent",
    "content_type": "Content-Type",
    "content_length": "Content-Length",
    "referer": "Referer",
    "cookie": "Cookie",
    "authorization": "Authorization",
    "origin": "Origin",
    "x_forwarded_for": "X-Forwarded-For",
    "x_real_ip": "X-Real-IP",
    "accept": "Accept",
    "accept_language": "Accept-Language",
    "x_requested_with": "X-Requested-With",
}


def parse_http_request(packet: Any) -> HttpRequest | None:
    """解析单个 PyShark 数据包为结构化 HTTP 请求字典。"""
    http = _value(packet, "http")
    ip = _value(packet, "ip") or _value(packet, "ipv6")
    tcp = _value(packet, "tcp")
    if http is None or ip is None or tcp is None or _is_http_response(http):
        return None

    method = _text(http, "request_method")
    request_uri = _text(http, "request_uri")
    if not method or not request_uri:
        return None

    try:
        uri = urlsplit(request_uri)
    except ValueError:
        return None

    query = _text(http, "request_uri_query") or uri.query
    headers = _headers(http)
    user_agent = headers.get("User-Agent", "")
    return {
        "src_ip": _text(ip, "src"),
        "dst_ip": _text(ip, "dst"),
        "src_port": _integer(tcp, "srcport"),
        "dst_port": _integer(tcp, "dstport"),
        "protocol": "HTTP",
        "timestamp": _timestamp(packet),
        "method": method,
        "host": _text(http, "host"),
        "path": uri.path or request_uri.split("?", 1)[0],
        "query": query,
        "query_params": _query_params(query),
        "headers": headers,
        "user_agent": user_agent,
        "body": _text(http, "file_data"),
        "status": 0,
    }


def parse_http_response_status(packet: Any) -> int | None:
    """读取单个 HTTP 响应的状态码，供 PCAP 请求响应关联使用。"""
    http = _value(packet, "http")
    if http is None or not _is_http_response(http):
        return None

    status = _integer(http, "response_code")
    return status if status is not None and 100 <= status <= 599 else None


def get_tcp_stream_id(packet: Any) -> str | None:
    """读取 PyShark TCP stream 标识，供离线请求响应关联使用。"""
    stream_id = _text(_value(packet, "tcp"), "stream")
    return stream_id or None


def _value(layer: Any, field: str) -> Any:
    """安全读取协议层字段值。"""
    try:
        return getattr(layer, field, None)
    except (AttributeError, TypeError, ValueError):
        return None


def _text(layer: Any, field: str) -> str:
    """安全读取协议层文本字段。"""
    value = _value(layer, field)
    if value is None:
        return ""
    try:
        return str(value)
    except (TypeError, ValueError):
        return ""


def _integer(layer: Any, field: str) -> int | None:
    """安全读取协议层整数字段。"""
    try:
        return int(_text(layer, field))
    except (TypeError, ValueError):
        return None


def _headers(http: Any) -> dict[str, str]:
    """提取已知的真实 HTTP 请求首部并统一名称。"""
    return {
        header: value
        for field, header in _HEADER_FIELDS.items()
        if (value := _text(http, field))
    }


def _query_params(query: str) -> dict[str, list[str]]:
    """解析查询参数，保留重复键和空值。"""
    params: dict[str, list[str]] = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        params.setdefault(key, []).append(value)
    return params


def _is_http_response(http: Any) -> bool:
    """判断 HTTP 层是否表示响应报文。"""
    return bool(_text(http, "response_code") or _text(http, "response"))


def _timestamp(packet: Any) -> str:
    """读取抓包时间并统一为 ISO 8601 字符串。"""
    value = _value(packet, "sniff_time")
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        value = _value(packet, "sniff_timestamp")
    if value is None:
        return ""
    try:
        return str(value)
    except (TypeError, ValueError):
        return ""
