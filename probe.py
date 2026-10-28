#!/usr/bin/env python3
"""经本机 Xray(每节点独立 socks 端口) 做真实链路拨测：出口 IP + 延迟。

严格不走系统代理/环境变量：自建 SOCKS5 客户端（socket 直连 127.0.0.1:<port>）。
判活标准 = 通过隧道拿到 HTTP 200 且解析出出口 IP（不是端口连通）。

用法:
  python probe.py                       # 拨测 xray_map.json 内全部端口
  python probe.py --workers 24 --timeout 12 --out probe_result.json
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import socket
import struct
import time

WORK = os.path.dirname(os.path.abspath(__file__))
IP_ECHO = [("208.95.112.1", 80, "/json/"), ("ip-api.com", 80, "/json/?fields=status,country,city,query")]


def socks5_get(proxy_port: int, host: str, port: int, path: str, timeout: float) -> tuple[int, bytes, float]:
    """返回 (status_code, 首包, ttfb_ms)。ttfb 才是真实链路延迟。"""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise OSError("socks5 auth fail")
        try:
            ip = ipaddress.ip_address(host)
            addr = b"\x01" + ip.packed if ip.version == 4 else b"\x04" + ip.packed
        except ValueError:
            hb = host.encode()
            addr = b"\x03" + bytes([len(hb)]) + hb
        s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
        rep = s.recv(4)
        if len(rep) < 2 or rep[1] != 0:
            raise OSError(f"socks5 connect rep={rep[1] if len(rep) > 1 else '?'}")
        # 消费 bound addr
        atyp = rep[3]
        if atyp == 1:
            s.recv(4 + 2)
        elif atyp == 4:
            s.recv(16 + 2)
        elif atyp == 3:
            ln = s.recv(1)[0]
            s.recv(ln + 2)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        _t = time.time()
        s.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        ttfb = (time.time() - _t) * 1000
        head, _, body = buf.partition(b"\r\n\r\n")
        code = 0
        if head.startswith(b"HTTP/"):
            try:
                code = int(head.split(b" ")[1])
            except Exception:
                code = 0
        return code, body, ttfb
    finally:
        try:
            s.close()
        except Exception:
            pass


def _parse_ip(body: bytes) -> str:
    try:
        js = json.loads(body.decode("utf-8", "replace"))
        return js.get("query") or js.get("ip") or ""
    except Exception:
        return ""


def probe_one(item: dict, timeout: float) -> dict:
    port, sip = item["port"], item["sip"]
    res = {"port": port, "sip": sip, "scc": item.get("scc"), "sn": item.get("sn"),
           "alive": False, "exit_ip": "", "latency_ms": None, "err": ""}
    for host, hport, path in IP_ECHO:
        t0 = time.time()
        try:
            code, body, ttfb = socks5_get(port, host, hport, path, timeout)
            dt = int(ttfb)
            ip = _parse_ip(body)
            if code == 200 and ip:
                res.update(alive=True, exit_ip=ip, latency_ms=dt)
                return res
            res["err"] = f"http={code} ip='{ip}'"
        except Exception as e:
            res["err"] = f"{type(e).__name__}:{str(e)[:40]}"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default=os.path.join(WORK, "xray_map.json"))
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--out", default=os.path.join(WORK, "probe_result.json"))
    args = ap.parse_args()

    items = json.load(open(args.map, encoding="utf-8"))
    t0 = time.time()
    out = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(lambda it: probe_one(it, args.timeout), items):
            out.append(r)
            flag = "OK " if r["alive"] else "DEAD"
            print(f"[{flag}] {r['port']} {r['scc']:<3} {r['sip']:<16} "
                  f"{('%.0fms' % r['latency_ms']) if r['latency_ms'] else '-':>7} "
                  f"{r['exit_ip'] or r['err']}")
    alive = [r for r in out if r["alive"]]
    json.dump(out, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    lats = sorted(r["latency_ms"] for r in alive)
    print(f"\n[=] {len(alive)}/{len(out)} 存活  用时 {time.time()-t0:.0f}s  "
          f"落盘 {args.out}")
    if lats:
        print(f"[=] 延迟 P50={lats[len(lats)//2]}ms P95={lats[int(len(lats)*0.95)]}ms "
              f"min={lats[0]}ms max={lats[-1]}ms  唯一出口IP={len({r['exit_ip'] for r in alive})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
