"""HaloVPN MITM capture addon — 只记录 halo/tapto/flowx 相关主机，落盘 JSONL。

运行: mitmdump -p 8890 -s capture.py --set connection_timeout=60
"""
import json
import os
import time

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture.jsonl")
WATCH = ("tapto", "flowx", "halo", "firebase", "tk0x1", "dns.sb", "taps")


def _hit(host: str) -> bool:
    h = (host or "").lower()
    return any(w in h for w in WATCH)


class Capture:
    def response(self, flow):
        host = flow.request.pretty_host
        if not _hit(host):
            return
        rec = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "req_headers": dict(flow.request.headers),
            "req_body": flow.request.get_text(strict=False)[:4000],
            "status": flow.response.status_code if flow.response else None,
            "resp_headers": dict(flow.response.headers) if flow.response else {},
            "resp_body": flow.response.get_text(strict=False)[:400000] if flow.response else "",
        }
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


addons = [Capture()]
