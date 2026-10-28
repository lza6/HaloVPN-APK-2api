#!/usr/bin/env python3
"""由 nodes_decrypted.json 生成单进程 Xray 配置：每节点一个 socks inbound + 专属 outbound。

用法:
  python gen_xray.py                # 全部节点 → xray_nodes.json
  python gen_xray.py --limit 40 --start-port 31000
"""
from __future__ import annotations

import argparse
import json
import os

WORK = os.path.dirname(os.path.abspath(__file__))


def build_vless_out(n: dict, tag: str) -> dict:
    addr = n["sip"] if int(n.get("rui") or 0) == 1 else (n.get("sd") or n["sip"])
    port = int(n.get("spr") or n.get("sp") or 443)
    user = {"id": n["d_px"], "encryption": "none"}
    flow = n.get("sf") or ""
    if flow:
        user["flow"] = flow
    stream = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "serverName": n.get("sni") or n.get("sd"),
            "fingerprint": "chrome",
            "publicKey": n.get("rpk"),
            "shortId": n.get("d_ssid") or "",
            "spiderX": "/",
        },
    }
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": addr, "port": port, "users": [user]}]},
        "streamSettings": stream,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", default=os.path.join(WORK, "nodes_decrypted.json"))
    ap.add_argument("--out", default=os.path.join(WORK, "xray_nodes.json"))
    ap.add_argument("--start-port", type=int, default=31000)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--alive", default="", help="只保留 probe 结果里存活的 sip（逗号分隔）")
    args = ap.parse_args()

    nodes = json.load(open(args.nodes, encoding="utf-8"))
    vl = [n for n in nodes if str(n.get("pt", "")).startswith("VL") and n.get("rpk")
          and n.get("d_px") and n.get("d_ssid")]
    if args.alive:
        keep = {x.strip() for x in args.alive.split(",") if x.strip()}
        vl = [n for n in vl if n["sip"] in keep]
    if args.limit:
        vl = vl[:args.limit]

    inbounds, outbounds, rules, mapping = [], [], [], []
    for i, n in enumerate(vl):
        port = args.start_port + i
        inbounds.append({
            "tag": f"s{i}", "listen": "127.0.0.1", "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        })
        outbounds.append(build_vless_out(n, f"o{i}"))
        rules.append({"type": "field", "inboundTag": [f"s{i}"], "outboundTag": f"o{i}"})
        mapping.append({"idx": i, "port": port, "sip": n["sip"], "scc": n.get("scc"),
                        "city": n.get("scity"), "sn": n.get("sn"), "sni": n.get("sni")})

    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    json.dump(cfg, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(mapping, open(os.path.join(WORK, "xray_map.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print(f"[=] {len(vl)} 节点 → {args.out} (socks {args.start_port}..{args.start_port+len(vl)-1})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
