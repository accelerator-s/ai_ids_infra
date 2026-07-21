"""生成 HTTP 明文 pcap 样本（纯 Python，无需 scapy）。

    python tests/pcaps/make_pcaps.py

每条请求都配一个响应包（同一 TCP 四元组，便于 tshark 归到同一 stream），
这样 pcap_analyzer 能把状态码关联回请求，暴力破解(401)/扫描(404) 才能端到端检出。
校验和只算 IP 首部，TCP 置 0（Wireshark 默认不校验）。生成后用 `tshark -r <file>` 核对。
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
SERVER = "192.168.1.10"
ATTACKER = "192.168.1.50"
USER = "192.168.1.77"
BASE_TS = 1_700_000_000.0
_REASON = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Server Error"}


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    tcp = struct.pack("!HHLLBBHHH", sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return eth + ip + tcp + payload


def _http_req(method: str, path: str, ua: str) -> bytes:
    return (f"{method} {path} HTTP/1.1\r\nHost: {SERVER}\r\n"
            f"User-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()


def _http_resp(status: int) -> bytes:
    return (f"HTTP/1.1 {status} {_REASON.get(status, 'OK')}\r\n"
            f"Server: demo\r\nContent-Length: 0\r\n\r\n").encode()


def _pair(ts: float, src_ip: str, sport: int, method: str, path: str,
          ua: str = "Mozilla/5.0", status: int = 200) -> list[tuple[float, bytes]]:
    """一条请求 + 其响应，共用同一四元组（同一 TCP stream）。"""
    return [
        (ts, _frame(src_ip, SERVER, sport, 80, _http_req(method, path, ua))),
        (ts + 0.01, _frame(SERVER, src_ip, 80, sport, _http_resp(status))),
    ]


def _write(name: str, packets: list[tuple[float, bytes]]) -> None:
    with open(OUT / name, "wb") as f:
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
            f.write(struct.pack("!IIII", sec, usec, len(data), len(data)) + data)
    print(f"  {name}  ({len(packets)} 包)")


def _one(name: str, path: str, ua: str = "Mozilla/5.0", method: str = "GET", status: int = 200) -> None:
    _write(name, _pair(BASE_TS, ATTACKER, 40000, method, path, ua, status))


if __name__ == "__main__":
    print("生成 pcap 样本：")

    # 内容型攻击：单请求 + 响应。查询串里的空格用 + 编码，否则请求行会被 tshark 按空格截断。
    _one("sample_sqli.pcap", "/item?id=1'+or+1=1+--")
    _one("sample_xss.pcap", "/search?q=<script>alert(1)</script>")
    _one("sample_cmdi.pcap", "/ping?host=127.0.0.1;cat+/etc/passwd")
    _one("sample_traversal.pcap", "/dl?file=../../../../etc/passwd")
    _one("sample_sensitive.pcap", "/.env", status=404)
    _one("sample_scanner.pcap", "/", ua="sqlmap/1.5.2")

    # 行为型：需要状态码，靠响应包关联
    brute: list[tuple[float, bytes]] = []
    for i in range(12):                                   # 5 分钟内 12 次登录失败 -> 暴力破解
        brute += _pair(BASE_TS + i * 15, ATTACKER, 41000 + i, "POST", "/login", status=401)
    _write("sample_bruteforce.pcap", brute)

    scan: list[tuple[float, bytes]] = []
    for i in range(45):                                   # 45 个不同路径且 404 -> 扫描器 + 大量 404
        scan += _pair(BASE_TS + i, ATTACKER, 42000 + i, "GET", f"/admin{i}.php", status=404)
    _write("sample_scan404.pcap", scan)

    high: list[tuple[float, bytes]] = []
    for i in range(120):                                  # 60s 内 120 次 -> 高频/DDoS
        high += _pair(BASE_TS + i * 0.4, ATTACKER, 43000 + i, "GET", f"/x?n={i}")
    _write("sample_highfreq.pcap", high)

    # 正常流量：慢速、干净，应零告警（端到端验证不误报）
    benign_paths = ["/", "/index.html", "/products", "/search?q=running+shoes",
                    "/about", "/blog/how-to-cook-rice", "/cart", "/contact"]
    benign: list[tuple[float, bytes]] = []
    for i, p in enumerate(benign_paths):
        benign += _pair(BASE_TS + i * 5, USER, 44000 + i, "GET", p)
    _write("sample_benign.pcap", benign)

    # 混合真实流量：正常里夹杂几条攻击，贴近真实抓包，适合现场演示
    mixed_reqs = [
        ("GET", "/", "Mozilla/5.0", 200),
        ("GET", "/search?q=hello", "Mozilla/5.0", 200),
        ("GET", "/item?id=1+union+select+pw+from+users", "Mozilla/5.0", 200),   # SQLi
        ("GET", "/about", "Mozilla/5.0", 200),
        ("GET", "/s?q=<script>alert(1)</script>", "Mozilla/5.0", 200),          # XSS
        ("GET", "/ping?host=1;cat+/etc/passwd", "Mozilla/5.0", 200),            # 命令注入
        ("GET", "/", "sqlmap/1.5.2", 200),                                      # 扫描器 UA
        ("GET", "/contact", "Mozilla/5.0", 200),
    ]
    mixed: list[tuple[float, bytes]] = []
    for i, (method, path, ua, status) in enumerate(mixed_reqs):
        mixed += _pair(BASE_TS + i * 3, ATTACKER, 45000 + i, method, path, ua, status)
    _write("sample_mixed.pcap", mixed)

    # 多源 IP：3 个正常 IP 慢速浏览 + 1 个攻击 IP 高频，验证只揪出攻击 IP、不误伤正常 IP
    multi: list[tuple[float, bytes]] = []
    for k in range(3):
        user_ip = f"192.168.1.{101 + k}"
        for i in range(5):
            multi += _pair(BASE_TS + i * 10 + k, user_ip, 46000 + k * 10 + i, "GET", f"/page{i}")
    for i in range(120):
        multi += _pair(BASE_TS + i * 0.4, "192.168.1.66", 47000 + i, "GET", "/account")
    multi.sort(key=lambda pkt: pkt[0])
    _write("sample_multi_ip.pcap", multi)

    print("完成，输出目录：", OUT)
