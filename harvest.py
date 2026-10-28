#!/usr/bin/env python3
"""HaloVPN v17.4.0 节点收割器 — 纯 HTTP 复现，无需 App / 模拟器。

协议栈
------
1) 域名发现：GET http://domain.taptoboy.com/api/domain/remote  (无鉴权, 返回 serverDomain 列表)
2) 设备注册：GET {host}/api/device/                            (拿 accountType/free 额度)
3) 节点列表：GET {host}/api/server/short/A/                    (全量节点, 字段加密)

签名：md5( SALT + "&".join(sorted(k=v)) + SALT )，k/v 用**未 URL 编码**的原值
会话密钥：客户端随机 16 字符 → RSA_PKCS1v15(INSIDE_PUBLIC_KEY) → base64 = 参数 key
节点字段：响应里 key 字段再 RSA 解出同一会话密钥，AES-128-CBC(IV=b"myhalovpnbestvpn") 解 p/px/pik/po/psk/ssid

用法
----
  python harvest.py                 # 单轮收割
  python harvest.py --count 3       # 连发 3 轮累积（服务端节点会轮换）
  python harvest.py --out nodes.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WORK = os.path.dirname(os.path.abspath(__file__))

# ---------------- 协议常量 ----------------
DOMAIN_DISCOVERY = "http://domain.taptoboy.com/api/domain/remote"
FALLBACK_HOSTS = [
    "http://taptobus.com", "http://taptodog.com", "http://taptocat.com",
    "http://taptobee.com", "http://taptocow.com", "http://taptoegg.com",
]
PATH_DEVICE = "/api/device/"
PATH_NODES = "/api/server/short/A/"
PKG = "com.thehot.halovpnpro"
PLATFORM = "android"
APP_VERSION = "17.4.0"
PROTOCOLS = "IK3,VL,VL-X,VL-R"
PROXIES = "IK,XX,XR,SX,IK-XX,IK-XR,IK-SX"
SIGN_SALT = "halo*^%)vpn&^$!@+halo"
AES_IV = b"myhalovpnbestvpn"

# libswan.so 内嵌 INSIDE_PRIVATE_KEY (PKCS#8, RSA-1024) —— 解响应 key 用
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
# 与上面私钥配对的公钥 (SubjectPublicKeyInfo)
INSIDE_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3lujCyi/VZU8tRKelL+H4dMdt3ShqfwxSdn2KXfhu"
    "0jD/XfKRh+cyg9hX9LTJOh0fM3ej/nEJZjJmbd7QmcF/O+iUyHUU4B0bGpuhL3urPsy/mMZF39BhVDXs"
    "gpXjDp6iR2X35LLGb4FynEzPk5nFlz6WeXmmvcGA29/xIGSWrwIDAQAB"
)

_UA = ("Mozilla/5.0 (Linux; Android 11; sdk_gphone_x86_64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36 okhttp/5.1.0")


# ---------------- 加密 / 签名 ----------------
def _load_keys():
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_der_private_key(
        base64.b64decode(INSIDE_PRIVATE_KEY_B64), password=None)
    pub = serialization.load_der_public_key(
        base64.b64decode(INSIDE_PUBLIC_KEY_B64))
    return priv, pub


def make_sign(params: dict) -> str:
    items = "&".join(f"{k}={params[k]}" for k in sorted(params))
    return hashlib.md5((SIGN_SALT + items + SIGN_SALT).encode()).hexdigest()


def rsa_wrap(plain: str, pub) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    return base64.b64encode(pub.encrypt(plain.encode(), padding.PKCS1v15())).decode()


def rsa_unwrap(blob_b64: str, priv) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    raw = base64.b64decode(blob_b64 + "=" * (-len(blob_b64) % 4))
    return priv.decrypt(raw, padding.PKCS1v15()).decode()


def aes_dec(blob_b64: str, key: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    raw = base64.b64decode(blob_b64 + "=" * (-len(blob_b64) % 4))
    dec = Cipher(algorithms.AES(key.encode()), modes.CBC(AES_IV)).decryptor()
    pt = dec.update(raw) + dec.finalize()
    return pt[:-pt[-1]].decode("utf-8", "replace")


def rand_token(n=16) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def rand_device_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


# ---------------- HTTP ----------------
PROXY_URL = ""  # 形如 http://127.0.0.1:10808；空 = 直连


def http_get(url: str, timeout=20):
    """直连优先；被 RST（CN 网络对 tapto* Host 的封锁）则回落到 PROXY_URL。"""
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "appVersion": APP_VERSION,
        "Accept": "application/json",
    })
    proxies = {"http": PROXY_URL, "https": PROXY_URL} if PROXY_URL else {}
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except (ConnectionResetError, urllib.error.URLError) as e:
        if not PROXY_URL:
            raise
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")


def discover_hosts() -> list[str]:
    """域名发现；失败则回落到内置列表。"""
    hosts = []
    try:
        q = {"platform": PLATFORM, "packageName": PKG,
             "simCountryCode": "US", "deviceCountry": "US", "appVersion": APP_VERSION}
        js = json.loads(http_get(DOMAIN_DISCOVERY + "?" + urllib.parse.urlencode(q), timeout=15))
        dom = ((js or {}).get("data") or {}).get("serverDomain") or ""
        hosts = [h.strip() for h in dom.split(",") if h.strip()]
        if hosts:
            print(f"[+] 域名发现成功，{len(hosts)} 个 host")
    except Exception as e:
        print(f"[!] 域名发现失败 ({type(e).__name__}), 用内置列表: {e}")
    for h in FALLBACK_HOSTS:
        if h not in hosts:
            hosts.append(h)
    return hosts


def register_device(host: str, device_id: str) -> dict:
    p = {"deviceId": device_id, "platform": PLATFORM, "packageName": PKG,
         "simCountryCode": "US", "deviceCountry": "US", "status": "off",
         "time": str(int(time.time() * 1000))}
    p["sign"] = make_sign(p)
    return json.loads(http_get(host + PATH_DEVICE + "?" + urllib.parse.urlencode(p)))


def fetch_nodes(host: str, device_id: str, app_sign: str = ""):
    """返回 (明文节点列表, 会话 AES 密钥)"""
    priv, pub = _load_keys()
    aes_key = rand_token(16)
    p = {
        "platform": PLATFORM, "packageName": PKG,
        "simCountryCode": "US", "deviceCountry": "US",
        "serverCountry": "",
        "serverProtocol": PROTOCOLS, "serverProxy": PROXIES,
        "time": str(int(time.time() * 1000)),
        "key": rsa_wrap(aes_key, pub),
        "appSign": app_sign,
    }
    p["sign"] = make_sign(p)
    query = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in p.items())
    body = json.loads(http_get(host + PATH_NODES + "?" + query))
    if body.get("code") != 200:
        raise RuntimeError(f"code={body.get('code')} msg={body.get('msg')}")
    resp_key = rsa_unwrap(body["key"], priv) if body.get("key") else aes_key
    return body["data"], resp_key


def decrypt_node(n: dict, key: str) -> dict:
    out = dict(n)
    for f in ("p", "px", "pik", "po", "psk", "ssid"):
        v = n.get(f)
        if not v:
            out["d_" + f] = ""
            continue
        try:
            out["d_" + f] = aes_dec(v, key)
        except Exception:
            out["d_" + f] = ""
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--out", default=os.path.join(WORK, "nodes_decrypted.json"))
    ap.add_argument("--proxy", default=os.environ.get("HALO_PROXY", "http://127.0.0.1:10808"))
    args = ap.parse_args()
    global PROXY_URL
    PROXY_URL = args.proxy

    hosts = discover_hosts()
    device_id = rand_device_id()
    all_nodes: dict[str, dict] = {}
    ok_host = None
    for host in hosts:
        try:
            dev = register_device(host, device_id)
            print(f"[+] {host} /api/device/ -> accountType="
                  f"{(dev.get('data') or {}).get('accountType')}")
            ok_host = host
            break
        except Exception as e:
            print(f"[-] {host} 设备注册失败: {type(e).__name__} {e}")
    if not ok_host:
        print("[x] 所有 host 均失败")
        return 1

    for i in range(args.count):
        try:
            nodes, key = fetch_nodes(ok_host, device_id)
        except Exception as e:
            print(f"[-] 第 {i+1} 轮失败: {type(e).__name__} {e}")
            continue
        for n in nodes:
            all_nodes[f"{n.get('sip')}|{n.get('sp')}|{n.get('pt')}"] = decrypt_node(n, key)
        print(f"[+] 第 {i+1} 轮: {len(nodes)} 条 (累积 {len(all_nodes)}), 会话密钥={key}")
        if i + 1 < args.count:
            time.sleep(2)

    nodes = list(all_nodes.values())
    json.dump(nodes, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"[=] 落盘 {args.out}  共 {len(nodes)} 节点")
    by_proto: dict[str, int] = {}
    for n in nodes:
        by_proto[n.get("pt", "?")] = by_proto.get(n.get("pt", "?"), 0) + 1
    print("[=] 协议分布:", by_proto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
