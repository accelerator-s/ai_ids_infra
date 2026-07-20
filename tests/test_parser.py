"""HTTP 协议解析：用假的 PyShark 包对象验证字段提取，无需 pyshark。"""

from types import SimpleNamespace

from app.protocol.packet_parser import parse_http_request, parse_http_response_status


def _packet(**layers) -> SimpleNamespace:
    base = {"http": None, "ip": None, "tcp": None, "sniff_time": None}
    base.update(layers)
    return SimpleNamespace(**base)


def test_parse_get_request():
    pkt = _packet(
        http=SimpleNamespace(request_method="GET", request_uri="/login?user=admin' or 1=1",
                             host="h", user_agent="sqlmap/1.0"),
        ip=SimpleNamespace(src="1.2.3.4", dst="5.6.7.8"),
        tcp=SimpleNamespace(srcport="5555", dstport="80"),
    )
    req = parse_http_request(pkt)
    assert req is not None
    assert req["method"] == "GET"
    assert req["path"] == "/login"
    assert "or 1=1" in req["query"]
    assert req["src_ip"] == "1.2.3.4"
    assert req["dst_port"] == 80
    assert req["user_agent"] == "sqlmap/1.0"
    assert req["headers"].get("User-Agent") == "sqlmap/1.0"


def test_non_http_packet_returns_none():
    assert parse_http_request(_packet()) is None


def test_response_status_extracted():
    resp = _packet(http=SimpleNamespace(response_code="404", response="1"))
    assert parse_http_response_status(resp) == 404
