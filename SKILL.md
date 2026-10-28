---
name: halovpn-node-pool
description: HaloVPN v17.4.0（com.thehot.halovpnpro）节点池逆向与接入技能卡——协议速查、收割/测活/转换层三条命令、必避坑。当需要复现该 App 的节点下发、刷新节点池、或把 socks 池接进 new-api 时使用。
---

# SKILL: HaloVPN 节点池逆向与接入

## 何时用

- 要复现 HaloVPN 的节点下发协议（自研 API + RSA/AES 三层加密）
- 要刷新 / 测活 / 评估这批节点的代理可用性
- 要把 38 条 VLESS-REALITY 节点变成 new-api 可用的 SOCKS5 出口
- 遇到同族 App（`tapto*` 域名、`libswan.so`、`sec*org.com` 家族）走同一套打法

## 状态（2026-10-29 实测）

| 能力 | 状态 |
|------|------|
| 协议还原（域名发现/签名/加密/字段） | ✅ 全通，签名可复算、144/144 节点解密成功 |
| VLESS-REALITY 建链 | ✅ 39/114 存活，双轮 38/38 稳定 |
| 吞吐 | ✅ 单流 P50 2.14 Mbps，4 并发聚合 ≈10 Mbps |
| 免 App 纯 HTTP 收割 | ⚠️ 未破（请求 key/appSign 私钥在服务端，原样重放 400） |
| App 缓存直取刷新 | ✅ `harvest_adb.py`（Room `swan_cache2`），需 App 走到主界面触发 |
| IKEv2（30 节点） | ⛔ 未接入（凭证已解出） |

## 三条命令跑通全流程

```bash
# 1) 刷新节点池（模拟器 adb root；App 有缓存时直接拉）
python harvest_adb.py --no-force          # → nodes_decrypted.json

# 2) 生成 Xray 配置 + 起 38 个 socks
python gen_xray.py --alive "<存活ip逗号分隔>" --out xray_alive.json
xray -test -c xray_alive.json && xray -c xray_alive.json

# 3) 真实拨测 + 吞吐 + demo
python probe.py --map xray_map.json --workers 12 --timeout 10
python speedtest.py --workers 6
python demo_server.py --port 8941         # 页面 / proxies.txt / sub / sub/clash
```

## 协议速查（详情 docs/PROTOCOL.md）

```
1. GET http://domain.taptoboy.com/api/domain/remote   → data.serverDomain 候选 host（零鉴权，中国可直连）
2. GET {host}/api/device/?deviceId=<16hex>&status=off&time=<ms>&sign   → accountType free/vip
3. GET {host}/api/server/short/A/?appSign&key&serverCountry=&serverProtocol=IK3,VL,VL-X,VL-R&serverProxy=...&time&sign
签名 = md5(SALT + sorted(k=v,"&") + SALT)      SALT 见 PROTOCOL.md 常量表
响应 key = RSA-1024(INSIDE 私钥, libswan.so 内嵌) → 16 字符会话密钥
字段 = AES-128-CBC(IV="myhalovpnbestvpn")     → UUID / shortId / PSK / 账号
VL-R = VLESS+REALITY+tcp+xtls-rprx-vision, fp=chrome, address=sip, serverName=sni
```

## 必避坑（每条都真踩过）

1. **Vision+REALITY 不能开 mux**：开了单流 0 字节，删掉即恢复。
2. **判活口径**：66% 失效节点端口照样通（SYN OK、TLS ClientHello 后 RST）→ 只认「HTTP 200 + 出口 IP」。
3. **签名必须用未编码原值**，空值参数（`serverCountry=`）也要参与。
4. **Room 是 WAL 模式**：`swanx.db` 必须连 `-wal`/`-shm` 一起 pull，否则空表。
5. **MMKV 缓存同步时间**：删库不够，要连 `files/mmkv` 一起删，否则 App 跳过联网。
6. **`tapto*` 域名按 Host 头被 RST**（80/443 都拦，CF 边缘 IP + Host 覆盖也拦），只有 `domain.taptoboy.com` 可直连。
7. **测延迟用 TTFB**：`Connection: close` 后按"收完"计时，会把 840 ms 算成 2.9 s。
8. **new-api 不验住宅清单出口**（`TraceProbes` 只拨 `source=="free"`）→ 出口正确性由转换层自证。
9. **模拟器 3 GB 内存下 Frida spawn 易超时**：用 `attach`；`frida-server` 与 `frida` pip 版本必须成对（16.5.9 配 16.5.9）。

## 合规

节点为运营商自营 VPS。凭证可解 ≠ 有使用权；进生产池属盗用第三方基础设施。研究可，商用自负。
