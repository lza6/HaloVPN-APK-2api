#!/usr/bin/env python3
"""HaloVPN 节点池刷新（模拟器 + App 缓存直取，无需 Frida / 无需 MITM）。

原理
----
App 拉到节点后会把「节点 JSON + RSA(会话密钥)」写进 Room 库
`/data/data/com.thehot.halovpnpro/databases/swanx.db` 的 `swan_cache2` 表
（`data` = 节点数组，`key` = clientKey）。模拟器 adb 已 root，直接 pull 出来，
用 libswan.so 内嵌的 INSIDE 私钥解 clientKey，再 AES-128-CBC 解节点字段即可。

相对 MITM 方案的好处：不需要证书、不需要 hook、掉线重试即可，40 秒一轮。

用法
----
  python harvest_adb.py              # 强制刷新：删库→启动→等 35s→pull→解析
  python harvest_adb.py --no-force   # 直接用现有缓存
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time

WORK = os.path.dirname(os.path.abspath(__file__))
PKG = "com.thehot.halovpnpro"
ACT = f"{PKG}/.ui.SplashActivity"
DB_REMOTE = f"/data/data/{PKG}/databases/swanx.db"
INSIDE_PRIVATE_KEY_B64 = (
    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALeW6MLKL9VlTy1Ep6Uv4fh0x23dKGp/"
    "DFJ2fYpd+G7SMP9d8pGH5zKD2Ff0tMk6HR8zd6P+cQlmMmZt3tCZwX876JTIdRTgHRsam6Eve6s+zL+Yx"
    "kXf0GFUNeyCleMOnqJHZffkssZvgXKcTM+TmcWXPpZ5eaa9wYDb3/EgZJavAgMBAAECgYBca7wBU4eBBd82"
    "CrnajqBTU3aR+CPAePTbDotkfKn0IBxKciEK4j+hTn46yRW5t2exrVctV4nQEYKNzgG9QaoGaMmzvb2dbUBW"
    "KM8gb0AXZ759ay9LvPuz/EXGEVECuMwbMzm4Z2oYqPeb8eSOqed1IQPKrQx/Vp8qr+Ak0JIHAQJBAOIyF9v5"
    "akfN0cKw+Gzo3SXWz0ZE31ijgRpL8p3vY59eA07bY/I+f9Eyso9dq5ulWnJDVp1WNOWbPqNpETvweWMCQQDP"
    "x6XWAEwn2JJF/3Hl1A6Yaxj4BlAV5D1m57knwuWovlrw7g6Zit7to2IeT7nUxb7Btx+yvYtlMmpUMLFUglVF"
    "AkAm/Z2RRKgmYnszBVB9bZKZcDLgmQSrAdxCTS8wPFC+6vTFBhpvaoib5hJTlkD7noA9zA/FJVQO9DjS8EyR"
    "OX2jAkEAhnoAqvCmWWOhyAv7+3OzvpISJvRvALwnwWJYQ5Owb/ZDhYuNh3KJteP4rQWMkFkrjNSof1aN0YE/"
    "sB2Tp85ywQJBAIP/gDnZEXnnmCG4oT48yHVsSdJkSeQRP6yDdL6ghyJCKlb3+mcSP4N2u+7i3/I1LgUfQPl/"
    "jNjmwdq17oFsJts="
)
AES_IV = b"myhalovpnbestvpn"
ADB = os.environ.get(
    "ADB_BIN",
    r"C:/Users/Administrator.DESKTOP-EGNE9ND/Downloads/Compressed/platform-tools/adb.exe")


def sh(*args: str, check: bool = False) -> str:
    p = subprocess.run([ADB, *args], capture_output=True, text=True,
                       env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    if check and p.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} -> {p.stderr.strip()}")
    return (p.stdout or "") + (p.stderr or "")


def force_refresh(wait: int = 35, reinstall: bool = False) -> None:
    sh("shell", "am", "force-stop", PKG)
    time.sleep(1)
    if reinstall:
        # 最可靠的触发方式：重装 = 数据全清 → 首次启动必然全量拉取
        apk = os.path.join(WORK, "..", "HaloVPN v17.4.0 b170400 (Premium by @ElaMods).apk")
        sh("uninstall", PKG)
        sh("push", os.path.abspath(apk), "/data/local/tmp/halo.apk")
        out = sh("shell", "pm", "install", "-r", "-g", "/data/local/tmp/halo.apk")
        print(f"[+] 重装 {PKG}: {out.strip().splitlines()[-1] if out.strip() else 'ok'}")
    # 删缓存表所在文件 → App 重新联网拉取
    # 只删库不够：App 用 MMKV 记住上次同步时间，会直接跳过联网
    sh("shell", f"rm -f /data/data/{PKG}/databases/swanx.db*")
    sh("shell", f"rm -rf /data/data/{PKG}/files/mmkv")
    sh("shell", "am", "start", "-n", ACT)
    print(f"[+] 已删缓存并启动 App，等待 {wait}s 让它拉完节点…")
    time.sleep(wait)


def pull_and_parse(out: str) -> list[dict]:
    import sqlite3
    local = os.path.join(WORK, "dbpull", "swanx.db")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    # Room 默认 WAL 模式：必须把 -wal / -shm 一起拉下来，否则主库是空壳
    for suffix in ("", "-wal", "-shm"):
        sh("pull", DB_REMOTE + suffix, local + suffix, check=True)
    c = sqlite3.connect(local)
    row = c.execute("select data, key from swan_cache2 order by id desc limit 1").fetchone()
    if not row:
        raise RuntimeError("swan_cache2 为空：App 还没写缓存（多等几秒或检查网络）")
    data, client_key = row

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    priv = serialization.load_der_private_key(
        base64.b64decode(INSIDE_PRIVATE_KEY_B64), password=None)
    aes_key = priv.decrypt(base64.b64decode(client_key), padding.PKCS1v15()).decode()

    def dec(v: str) -> str:
        raw = base64.b64decode(v + "=" * (-len(v) % 4))
        d = Cipher(algorithms.AES(aes_key.encode()), modes.CBC(AES_IV)).decryptor()
        pt = d.update(raw) + d.finalize()
        return pt[:-pt[-1]].decode("utf-8", "replace")

    nodes = json.loads(data)
    for n in nodes:
        n["d_px"] = dec(n["passwordXray"]) if n.get("passwordXray") else ""
        n["d_ssid"] = dec(n["serverShortId"]) if n.get("serverShortId") else ""
        n["d_pik"] = dec(n["passwordIk"]) if n.get("passwordIk") else ""
        n["d_psk"] = dec(n["psk"]) if n.get("psk") else ""
        n["d_po"] = dec(n["passwordObfs"]) if n.get("passwordObfs") else ""
        n["d_p"] = dec(n["password"]) if n.get("password") else ""
        # 与 HTTP 版字段对齐，方便 gen_xray.py 复用
        n.setdefault("sip", n.get("serverIp"))
        n.setdefault("spt", n.get("serverPortTls"))
        n.setdefault("spr", n.get("serverPortReality"))
        n.setdefault("sni", n.get("serverSni"))
        n.setdefault("rpk", n.get("rayPubkey"))
        n.setdefault("sf", n.get("serverFlow"))
        n.setdefault("scc", n.get("serverCountryCode"))
        n.setdefault("scity", n.get("serverCity"))
        n.setdefault("sn", n.get("serverName"))
        n.setdefault("st", n.get("serverType"))
        n.setdefault("rui", n.get("rayUseIp"))
        n["pt"] = n.get("serverProtocol")
    json.dump(nodes, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[=] {len(nodes)} 节点 → {out}   会话密钥={aes_key}")
    return nodes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-force", action="store_true")
    ap.add_argument("--reinstall", action="store_true", help="重装 APK 强制全量拉取（最可靠）")
    ap.add_argument("--wait", type=int, default=35)
    ap.add_argument("--out", default=os.path.join(WORK, "nodes_decrypted.json"))
    args = ap.parse_args()
    if not args.no_force:
        force_refresh(args.wait, reinstall=args.reinstall)
    nodes = pull_and_parse(args.out)
    from collections import Counter
    print("[=] 协议分布:", dict(Counter(n.get("pt") for n in nodes)))
    print("[=] 国家数:", len({n.get("scc") for n in nodes}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
