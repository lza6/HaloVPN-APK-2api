#!/usr/bin/env python3
"""HaloVPN 节点池 demo 服务（本地验证用）。

端点
  GET /                  demo 页面（节点表 / 存活 / 出口IP / 延迟）
  GET /api/nodes         节点明细 JSON（凭证脱敏）
  GET /api/stats         汇总统计
  GET /api/probe         触发一轮真实拨测（后台线程，返回 202）
  GET /proxies.txt       socks5 清单（new-api TRYINGOPEN_PROXY_FILE 可直接读）
  GET /sub               vless:// 订阅（base64，给客户端导入）
  GET /sub/clash         Clash/mihomo YAML 订阅
  GET /health            健康检查

前置：本机已用 xray_alive.json 起好 38 个 socks 端口（127.0.0.1:31000+i）。

用法: python demo_server.py [--port 8940]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import probe as P

WORK = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(WORK, "demo_snapshot.json")
LOCK = threading.Lock()
STATE = {"last_probe": 0, "probing": False, "rounds": 0}


def _load(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def build_snapshot() -> dict:
    mapping = _load(os.path.join(WORK, "xray_map.json"), [])
    nodes = _load(os.path.join(WORK, "nodes_decrypted.json"), [])
    probe = {r["port"]: r for r in _load(os.path.join(WORK, "probe_final.json"), [])}
    speed = {r["port"]: r for r in _load(os.path.join(WORK, "speed_result.json"), [])}
    by_sip = {}
    for n in nodes:
        by_sip.setdefault(n.get("sip"), n)
    out = []
    for m in mapping:
        pr = probe.get(m["port"], {})
        n = by_sip.get(m["sip"], {})
        out.append({
            "socks_port": m["port"],
            "socks": f"socks5://127.0.0.1:{m['port']}",
            "name": m.get("sn"), "country": m.get("scc"), "city": m.get("city"),
            "server_ip": m["sip"], "sni": m.get("sni"),
            "protocol": n.get("pt"), "tier": n.get("st"),
            "uuid": (n.get("d_px") or "")[:8] + "...",  # 脱敏
            "short_id": n.get("d_ssid"),
            "reality_pubkey": (n.get("rpk") or "")[:10] + "...",
            "flow": n.get("sf"),
            "alive": bool(pr.get("alive")),
            "exit_ip": pr.get("exit_ip", ""),
            "latency_ms": pr.get("latency_ms"),
            "mbps": (speed.get(m["port"]) or {}).get("mbps"),
        })
    return {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "nodes": out}


def snapshot() -> dict:
    with LOCK:
        if os.path.exists(SNAPSHOT):
            return _load(SNAPSHOT, {"nodes": []})
        snap = build_snapshot()
        json.dump(snap, open(SNAPSHOT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        return snap


def run_probe(workers: int = 12, timeout: float = 10) -> None:
    with LOCK:
        if STATE["probing"]:
            return
        STATE["probing"] = True
    try:
        mapping = _load(os.path.join(WORK, "xray_map.json"), [])
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            res = list(ex.map(lambda it: P.probe_one(it, timeout), mapping))
        json.dump(res, open(os.path.join(WORK, "probe_final.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        STATE["last_probe"] = int(time.time())
        STATE["rounds"] += 1
        if os.path.exists(SNAPSHOT):
            os.remove(SNAPSHOT)
        build_snapshot()
    finally:
        with LOCK:
            STATE["probing"] = False


def vless_uris(snap: dict) -> list[str]:
    nodes = _load(os.path.join(WORK, "nodes_decrypted.json"), [])
    by_sip = {}
    for n in nodes:
        by_sip.setdefault(n.get("sip"), n)
    out = []
    for item in snap["nodes"]:
        n = by_sip.get(item["server_ip"])
        if not n or not n.get("d_px"):
            continue
        q = (f"encryption=none&security=reality&sni={n['sni']}&fp=chrome"
             f"&pbk={n['rpk']}&sid={n['d_ssid']}&type=tcp&flow={n.get('sf') or 'xtls-rprx-vision'}")
        name = f"halo-{item['country']}-{item['server_ip']}"
        from urllib.parse import quote
        out.append(f"vless://{n['d_px']}@{n['sip']}:443?{q}#{quote(name)}")
    return out


def clash_yaml(snap: dict) -> str:
    nodes = _load(os.path.join(WORK, "nodes_decrypted.json"), [])
    by_sip = {}
    for n in nodes:
        by_sip.setdefault(n.get("sip"), n)
    lines = ["mixed-port: 7890", "mode: rule", "log-level: warning", "proxies:"]
    names = []
    for item in snap["nodes"]:
        n = by_sip.get(item["server_ip"])
        if not n:
            continue
        name = f"halo-{item['country']}-{item['server_ip']}"
        names.append(name)
        lines += [
            f"  - name: \"{name}\"",
            "    type: vless",
            f"    server: {n['sip']}",
            "    port: 443",
            f"    uuid: {n['d_px']}",
            "    network: tcp",
            "    tls: true",
            f"    flow: {n.get('sf') or 'xtls-rprx-vision'}",
            "    servername: " + str(n['sni']),
            "    reality-opts:",
            f"      public-key: {n['rpk']}",
            f"      short-id: \"{n['d_ssid']}\"",
            "    client-fingerprint: chrome",
        ]
    lines.append("proxy-groups:")
    lines.append("  - name: halo")
    lines.append("    type: select")
    lines.append("    proxies: [" + ", ".join(f'"{x}"' for x in names) + "]")
    lines.append("rules:")
    lines.append("  - MATCH,halo")
    return "\n".join(lines) + "\n"


PAGE = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HaloVPN 节点池 · 本地验证</title>
<style>
:root{--bg:#0b0f14;--card:#121821;--line:#1e2836;--fg:#e6edf3;--dim:#8b9bb0;--ok:#2ea043;--bad:#d1242f;--acc:#3b82f6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
h1{font-size:17px;margin:0;font-weight:600}
.pill{background:#16202c;border:1px solid var(--line);padding:3px 9px;border-radius:999px;color:var(--dim);font-size:12px}
button{background:var(--acc);color:#fff;border:0;padding:8px 14px;border-radius:8px;cursor:pointer;font-size:13px}
button:disabled{opacity:.5;cursor:default}
main{padding:16px 22px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--dim);font-weight:500;position:sticky;top:0;background:var(--bg)}
tr:hover td{background:#0f1620}
.ok{color:var(--ok)}.bad{color:var(--bad)}.mono{font-family:ui-monospace,Consolas,monospace}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:20px;margin-top:4px}
.kpi span{color:var(--dim);font-size:12px}
a{color:var(--acc)}
</style></head><body>
<header>
  <h1>HaloVPN v17.4.0 → 节点池</h1>
  <span class="pill" id="gen">-</span>
  <span class="pill" id="state">-</span>
  <button id="refresh">重新拨测</button>
  <a class="pill" href="/proxies.txt">proxies.txt</a>
  <a class="pill" href="/sub">vless 订阅</a>
  <a class="pill" href="/sub/clash">clash 订阅</a>
</header>
<main>
  <div class="grid">
    <div class="kpi"><span>节点总数</span><b id="k_total">-</b></div>
    <div class="kpi"><span>真实存活</span><b id="k_alive" class="ok">-</b></div>
    <div class="kpi"><span>唯一出口 IP</span><b id="k_ip">-</b></div>
    <div class="kpi"><span>延迟 P50</span><b id="k_p50">-</b></div>
    <div class="kpi"><span>延迟 P95</span><b id="k_p95">-</b></div>
  </div>
  <table><thead><tr>
    <th>#</th><th>状态</th><th>国家</th><th>城市</th><th>节点</th><th>服务端 IP</th>
    <th>socks 端口</th><th>出口 IP</th><th>延迟</th><th>单流</th><th>SNI</th>
  </tr></thead><tbody id="rows"></tbody></table>
</main>
<script>
const fmt = n => n==null ? '-' : Number(n).toFixed(0)+'ms';
const flag = cc => cc ? String.fromCodePoint(...[...cc.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65)) : '';
async function load(){
  const r = await fetch('/api/nodes'); const d = await r.json();
  const ns = d.nodes || [];
  document.getElementById('gen').textContent = '生成于 ' + (d.generated_at||'-');
  const alive = ns.filter(n=>n.alive);
  const lats = alive.map(n=>n.latency_ms).filter(Boolean).sort((a,b)=>a-b);
  document.getElementById('k_total').textContent = ns.length;
  document.getElementById('k_alive').textContent = alive.length;
  document.getElementById('k_ip').textContent = new Set(alive.map(n=>n.exit_ip)).size;
  document.getElementById('k_p50').textContent = lats.length?fmt(lats[Math.floor(lats.length/2)]):'-';
  document.getElementById('k_p95').textContent = lats.length?fmt(lats[Math.floor(lats.length*0.95)]):'-';
  document.getElementById('rows').innerHTML = ns.map((n,i)=>`<tr>
    <td>${i+1}</td>
    <td class="${n.alive?'ok':'bad'}">${n.alive?'● 存活':'○ 失败'}</td>
    <td>${flag(n.country)} ${n.country||'-'}</td>
    <td>${n.city||'-'}</td>
    <td class="mono">${n.name||'-'}</td>
    <td class="mono">${n.server_ip}</td>
    <td class="mono">${n.socks_port}</td>
    <td class="mono">${n.exit_ip||'-'}</td>
    <td>${fmt(n.latency_ms)}</td>
    <td>${n.mbps?Number(n.mbps).toFixed(1)+'M':'-'}</td>
    <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis">${n.sni||'-'}</td>
  </tr>`).join('');
}
document.getElementById('refresh').onclick = async e => {
  e.target.disabled = true; e.target.textContent = '拨测中…';
  await fetch('/api/probe');
  const t = setInterval(async ()=>{
    const s = await (await fetch('/api/stats')).json();
    if(!s.probing){ clearInterval(t); e.target.disabled=false; e.target.textContent='重新拨测'; load(); }
  }, 2000);
};
load();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HaloPoolDemo/1.0"

    def _send(self, code: int, body: bytes, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if path == "/health":
            return self._send(200, b'{"ok":true}')
        if path == "/api/stats":
            snap = snapshot()
            alive = [n for n in snap["nodes"] if n["alive"]]
            return self._send(200, json.dumps({
                "total": len(snap["nodes"]), "alive": len(alive),
                "unique_exit_ip": len({n["exit_ip"] for n in alive}),
                "probing": STATE["probing"], "rounds": STATE["rounds"],
                "last_probe": STATE["last_probe"],
                "generated_at": snap.get("generated_at"),
            }, ensure_ascii=False).encode())
        if path == "/api/nodes":
            return self._send(200, json.dumps(snapshot(), ensure_ascii=False).encode())
        if path == "/api/probe":
            threading.Thread(target=run_probe, daemon=True).start()
            return self._send(202, b'{"accepted":true}')
        if path == "/proxies.txt":
            snap = snapshot()
            body = "# HaloVPN socks 池（每行一个，new-api: TRYINGOPEN_PROXY_FILE 可直接读）\n"
            body += "".join(f"{n['socks']}\n" for n in snap["nodes"] if n["alive"])
            return self._send(200, body.encode(), "text/plain; charset=utf-8")
        if path == "/sub":
            uris = vless_uris(snapshot())
            blob = base64.b64encode("\n".join(uris).encode()).decode()
            return self._send(200, blob.encode(), "text/plain; charset=utf-8")
        if path == "/sub/clash":
            return self._send(200, clash_yaml(snapshot()).encode(), "text/yaml; charset=utf-8")
        return self._send(404, b'{"error":"not found"}')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8940)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[=] demo 服务 http://127.0.0.1:{args.port}  节点 {len(snapshot()['nodes'])} 条")
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
