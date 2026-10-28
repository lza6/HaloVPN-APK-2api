# HaloVPN 节点下发协议（实现手册）

> 面向二次开发 / 对接方。所有结论均在真机（Android 11 模拟器）+ 真实请求上验证过。
> 标 `已验证` = 实际跑通并观察到结果；`静态确认` = 读反编译代码确认；`待验证` = 未跑通。

## 1. 常量表

| 名称 | 值 |
|------|-----|
| 包名 | `com.thehot.halovpnpro` |
| 版本 | `17.4.0`（versionCode 170400） |
| 签名 SALT | `halo*^%)vpn&^$!@+halo` |
| AES IV（节点字段） | `myhalovpnbestvpn`（ASCII 16 字节，硬编码在 `v7.a.f37752a`） |
| 节点池 host（RC 默认） | `https://www.taptobus.live`；多源 `http://taptobus.com,taptocat.com,taptodog.com,taptoegg.com` |
| 域名发现 host | `http://domain.taptoboy.com`（`http://47.74.231.28` 为 debug 备用） |
| DoH | `https://doh.dns.sb/dns-query?ct=application/dns-json` |
| 账号/IAP 后端 | `https://flowxspace.com/api/v1/...`（`client_id=halopro-android`）、`https://key.flowxspace.com/api` |
| Firebase | projectNumber `924704781957`，appId `1:924704781957:android:3a5d331d573c37a466dbec`，apiKey `AIzaSyDpLVm0imjR4y8VsGgwEiiePqTRpVU-jwk` |
| RC 关键键 | `server_host_url` / `server_host_url_multi` / `server_remote_url` / `server_nodes_cache_duration` / `fix_cache` / `fix_cache_vl` / `cf_best_ip_range` |
| 协议族标识 | `IK3,VL,VL-X,VL-R`（`serverProtocol`）、`IK,XX,XR,SX,IK-XX,IK-XR,IK-SX`（`serverProxy`） |

## 2. 域名发现（零鉴权，已验证）

```
GET http://domain.taptoboy.com/api/domain/remote
    ?appVersion=17.4.0&deviceCountry=US&packageName=com.thehot.halovpnpro
    &platform=android&simCountryCode=US
```

响应（实测）：

```json
{"code":200,"msg":"success","desc":"slave7","data":{
  "serverDomain":"http://taptobee.com,http://taptocow.com,http://taptodog.com,http://taptoegg.com",
  "vlCountry":"IR","tCountry":"IR,TM,MM,AZ,PK,AF,ID,TR,JO,KH,BD,PH,TH,VN,NG,ET,RU,UA,IN,EG,IQ,DZ,KZ,UZ,MA,BR,MX,AR,CL,CO,PE,ZA",
  "geoCountry":"CN","preServer":"40.160.61.67","dServer":"40.160.53.78",
  "vDns":"1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4","ikWait":15,"vlWait":20,"resolvedCountry":"US","countrySource":"SIM"}}
```

- 该接口对**中国直连可用**（其余 `tapto*` 主机名被 RST，见第 7 节）。
- `serverDomain` 是节点池的候选 host 列表，App 用它做 failover。

## 3. 设备注册（已验证，可自造）

```
GET {host}/api/device/
    ?deviceCountry=US&deviceId=<16 hex>&packageName=com.thehot.halovpnpro
    &platform=android&sign=<md5>&simCountryCode=US&status=off&time=<ms>
```

- `deviceId`：16 位小写 hex，客户端随机生成即可（实测自造随机值同样 200）。
- `sign`：见第 4 节。
- 响应关键字段：`data.accountType`（`free`/`vip`）、`vipExpiresDateMs`、`serverTime`。
- 实测自造请求返回 `accountType=free`，说明设备注册**不校验真机指纹**。

## 4. 签名（已验证，两种接口同一算法）

```
sign = md5( SALT + "&".join(f"{k}={v}" for k in sorted(params)) + SALT )
```

- 参与签名的 `v` 是**未 URL 编码的原值**（`key` / `appSign` 里的 `+` `/` `=` 必须保持原样再算 md5）。
- **空值也参与**：`serverCountry=` 会以 `serverCountry=` 形式进入签名串。
- 复算验证：抓包的 `/api/device/` 签名 `581ed599...`、`/api/server/short/A/` 签名 `3ca22882...` 均**精确命中**。

## 5. 节点列表（核心端点）

```
GET {host}/api/server/short/A/
    ?appSign=<RSA blob>&deviceCountry=US&key=<RSA blob>&packageName=com.thehot.halovpnpro
    &platform=android&serverCountry=&serverProtocol=IK3,VL,VL-X,VL-R
    &serverProxy=IK,XX,XR,SX,IK-XX,IK-XR,IK-SX&simCountryCode=US&time=<ms>&sign=<md5>
```

响应（结构，实测 124 809 字节 / 144 条）：

```json
{"code":200,"msg":"success","desc":"slave7",
 "key":"<172 字符 base64 = RSA-1024(会话密钥)>",
 "data":[{
   "sn":"RO-BUH-8745","sip":"45.82.102.22","scc":"RO","scity":"Bucharest",
   "sd":"origin-87459710.sec0org.com","sni":"origin-87459710.sec0org.com",
   "st":"vip","pt":"VL-R","sp":443,"spr":443,
   "rss":"reality","rn":"tcp","rpk":"<reality 公钥 base64url>","sf":"xtls-rprx-vision",
   "rui":1,"rp":"/jkgxws","re":"none","rht":"none",
   "a":"halovpn","p":"<AES>","px":"<AES>","pik":"<AES>","po":"<AES>","psk":"<AES>","ssid":"<AES>"}]}
```

### 字段表

| 字段 | 含义 | 处理后 |
|------|------|--------|
| `sn` | 节点名（`国家-城市-编号`） | 展示用 |
| `sip` / `oip` | 服务端 IP / 出口 IP | `sip` 建链 |
| `sd` / `scfd` / `sni` | 域名 / CF 域名 / TLS SNI | REALITY `serverName` |
| `scc` / `scity` | 国家码 / 城市 | 分组 |
| `st` | `free` / `vip`（决定 App 侧是否可点） | 服务端不拦，见报告 |
| `pt` | 协议：`VL-R`(VLESS+REALITY+tcp)、`VL-X`、`VL`、`IK2`/`IK3`(IKEv2) | 选建链方式 |
| `sp` / `spr` / `spt` / `spw` / `spg` / `sph` | 各协议端口（reality/ws/grpc/hy2/tls） | VL-R 用 `spr` |
| `sf` | `xtls-rprx-vision`（VLESS flow） | outbound `flow` |
| `rss` / `rn` / `rp` / `rpk` / `rht` | reality/网络/路径/公钥/头类型 | REALITY 参数 |
| `rui` | 1=用 IP 建链，0=用域名 | address 选择 |
| `a` | 账号名（`halovpn`，IKE 用） | IKE 认证 |
| `p` / `px` | VLESS 用户标识（AES） | `px` 解出即 UUID |
| `ssid` | REALITY shortId（AES） | REALITY `shortId` |
| `pik` / `psk` / `po` | IKEv2 账号 / 预共享密钥 / obfs 口令（AES） | strongSwan 侧 |

### 解密（已验证，144/144 全成功）

```python
# 1) 响应 key → 会话密钥。libswan.so 内嵌 INSIDE_PRIVATE_KEY(PKCS#8,1024)
aes_key = RSA_PKCS1v15_decrypt(b64decode(resp["key"]), INSIDE_PRIVATE_KEY)   # → 16 字符
# 2) 节点字段
pt = AES_128_CBC(b64decode(field), key=aes_key, iv=b"myhalovpnbestvpn")
pt = strip_pkcs5(pt)                                                          # → UUID / shortId / 账号 / PSK
```

实测样例（脱敏）：`px → 4dcd875a-****-****-****-************`、`ssid → edb42d4a`、`psk → PSK*********AUTH`。

### 建链（VL-R，已验证 38/38）

```json
{"protocol":"vless","settings":{"vnext":[{"address":"<sip>","port":443,
  "users":[{"id":"<px>","encryption":"none","flow":"xtls-rprx-vision"}]}]},
 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
   "serverName":"<sni>","fingerprint":"chrome","publicKey":"<rpk>",
   "shortId":"<ssid>","spiderX":"/"}}}
```

- `mux` **不可开**：Vision+REALITY 下开 mux 实测链路 0 字节（已回退）。
- 单流 ≈2.1–2.9 Mbps，4 并发聚合 ≈10 Mbps。

## 6. 内置兜底数据（无需联网即可拿到 20 条）

| 文件 | 内容 |
|------|------|
| `assets/vl_cache.json` | 20 条 VL-X 节点（US×10 + FR×10，`st=free`） |
| `assets/ik_cache.json` | 同一批节点的 IKEv2 形态 |
| `assets/key_cache.json` | 上述缓存的会话密钥 RSA 密文（同样用 INSIDE 私钥解出 `1sFq4na8JU7p1X56`） |
| `assets/v2ray_config*.json` | v2rayNG 模板（`v2ray.cool` 占位，非真实节点） |

## 7. 必避坑

1. **`taptus*` 主机在中国直连会被 RST**：`taptobus/taptodog/taptocat/taptobee/taptocow/taptoegg` 全部在 ~200 ms 后 RST
   （HTTP 80 与 HTTPS 443 一样，且用可达 CF 边缘 IP + `Host:` 覆盖也 RST ⇒ 按 Host 封锁）。
   只有 `domain.taptoboy.com` 可直连。收割要么走境外出口，要么把 `harvest.py --proxy` 指向本地代理。
2. **响应 `key` 只认 INSIDE 私钥**：请求里的 `key`/`appSign` 是另一对密钥（`libswan.so` 里只有公钥 `SWAN_PUBLIC_KEY`），
   服务端会解这两项；目前**无法自造**（见报告“未破点”）。原样重放也不行（服务端有一次性/时效校验）。
3. **`sign` 必须用未编码原值算**，`+`→`%2B` 之后再算 md5 会错。
4. **TTFB 才是延迟**：`Connection: close` 后会等 socket 关闭，按“收完”计时会把 840 ms 算成 2.9 s。
5. **死节点多数 TCP 可达**（11/15 抽样 SYN OK，TLS ClientHello 后 RST），所以“端口连通”不能当存活判据。
6. **模拟器不稳**：76 MB 级 dex + 内存 3 GB 的 AVD，`pm clear` 后 `frida spawn` 易超时；用 `attach` 更稳。
7. Git Bash 下调用 adb 传 `/data/local/tmp/...` 需 `MSYS_NO_PATHCONV=1`，否则被改写成 Windows 路径。

## 8. 最小实现骨架

```python
import hashlib, time, base64, urllib.parse, urllib.request
SALT = "halo*^%)vpn&^$!@+halo"

def sign(p):
    items = "&".join(f"{k}={p[k]}" for k in sorted(p))
    return hashlib.md5((SALT + items + SALT).encode()).hexdigest()

p = {"deviceId": "0123456789abcdef", "platform": "android",
     "packageName": "com.thehot.halovpnpro", "simCountryCode": "US",
     "deviceCountry": "US", "status": "off", "time": str(int(time.time()*1000))}
p["sign"] = sign(p)
q = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in p.items())
print(urllib.request.urlopen(f"http://taptodog.com/api/device/?{q}").read())   # 需境外出口
```
