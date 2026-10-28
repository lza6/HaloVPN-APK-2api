#!/usr/bin/env python3
"""存活节点吞吐测试：经各自 socks 端口下载 1MB，统计有效带宽。

用法: python speedtest.py [--bytes 1000000] [--workers 6]
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


def fetch(proxy_port: int, host: str, path: str, timeout: float) -> tuple[int, int, float]:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        try:
            ip = ipaddress.ip_address(host)
            addr = b"\x01" + ip.packed
        except ValueError:
            hb = host.encode()
            addr = b"\x03" + bytes([len(hb)]) + hb
        s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", 80))
        rep = s.recv(4)
        atyp = rep[3]
        if atyp == 1:
            s.recv(6)
        elif atyp == 3:
            ln = s.recv(1)[0]
            s.recv(ln + 2)
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: curl/8\r\nConnection: close\r\n\r\n").encode())
        t0 = time.time()
        total, buf = 0, b""
        t0 = time.time()
        while True:
            try:
                chunk = s.recv(65536)
            except (socket.timeout, ConnectionResetError):
                break
            if not chunk:
                break
            if not buf:
                head, _, rest = chunk.partition(b"\r\n\r\n")
                buf = b"hdr"
                total += len(rest)
            else:
                total += len(chunk)
            if time.time() - t0 > timeout:
                break
        return total, int((time.time() - t0) * 1000), 0
    finally:
        try:
            s.close()
        except Exception:
            pass


def one(item: dict, nbytes: int, timeout: float) -> dict:
    try:
        total, ms, _ = fetch(item["port"], "speed.cloudflare.com", f"/__down?bytes={nbytes}", timeout)
    except Exception as e:
        return {"port": item["port"], "scc": item.get("scc"), "bytes": 0, "ms": 0,
                "mbps": 0.0, "err": f"{type(e).__name__}"}
    mbps = (total * 8 / (ms / 1000) / 1e6) if ms and total else 0.0
    return {"port": item["port"], "scc": item.get("scc"), "bytes": total,
            "ms": ms, "mbps": round(mbps, 2), "err": ""}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default=os.path.join(WORK, "xray_map_alive.json"))
    ap.add_argument("--bytes", type=int, default=1000000)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out", default=os.path.join(WORK, "speed_result.json"))
    args = ap.parse_args()
    items = json.load(open(args.map, encoding="utf-8"))
    out = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(lambda it: one(it, args.bytes, args.timeout), items):
            out.append(r)
            print(f"[{r['port']}] {r['scc']:<3} {r['bytes']/1024:8.1f}KB "
                  f"{r['ms']:6d}ms  {r['mbps']:7.2f} Mbps")
    json.dump(out, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    good = [r for r in out if r["mbps"] > 0.2]
    if good:
        v = sorted(r["mbps"] for r in good)
        print(f"\n[=] 有效吞吐节点 {len(good)}/{len(out)}  P50={v[len(v)//2]}Mbps "
              f"max={v[-1]}Mbps  落盘 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
