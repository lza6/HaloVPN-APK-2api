# HaloVPN v17.4.0 (com.thehot.halovpnpro) — 逆向 / 节点池 / 代理池评估

> 目标 APK：`HaloVPN v17.4.0 b170400 (Premium by @ElaMods).apk`（98 MB，arm64 + armeabi-v7a，ElaMods 破解版）
> 结论先行：**协议全还原（零鉴权可复现），节点池可榨**。一轮 114 个 VLESS-REALITY 节点中 38 个真实握手存活，
> 38 个**独立出口 IP**、24 个国家、TTFB P50 **840 ms**、单流 P50 **2.14 Mbps**（4 并发聚合 ≈10 Mbps）。

| 项目 | 状态 | 证据 |
|------|------|------|
| APK 架构判定 | ✅ | v2rayNG 内核（`libgojni.so`）+ strongSwan IKEv2 + hev-socks5-tunnel |
| 后端域名 | ✅ | `flowxspace.com`（账号/IAP）+ `taptobus.com` 等节点池 + `domain.taptoboy.com` 域名发现 |
| 节点列表接口 | ✅ 静态确认 + 抓包实证 | `GET /api/server/short/A/`（144 条，含 vip 114 + free 30） |
| 签名算法 | ✅ 已验证（两种接口签名复算命中） | `md5(SALT + sorted(k=v,&) + SALT)`，`SALT=halo*^%)vpn&^$!@+halo` |
| 节点字段加密 | ✅ 已验证（全部 144 条解密成功） | 响应 `key` = RSA-1024(INSIDE 公钥) → 16 字符会话密钥 → AES-128-CBC，IV=`myhalovpnbestvpn` |
| RSA 私钥 | ✅ 静态提取 | `libswan.so` 内嵌 `INSIDE_PRIVATE_KEY`（PKCS#8，1024-bit） |
| VLESS-REALITY 建链 | ✅ 实测 38/38 存活 | Xray 26.10.21，`flow=xtls-rprx-vision`，`fp=chrome` |
| 吞吐 | ✅ 实测 | 单流 P50 2.14 Mbps / max 2.88；4 并发聚合 ≈9.7–10.9 Mbps |
| IK2(30 节点) | ⛔ 未接入 | IKEv1/IKEv2（strongSwan），需 PSK+账号，本轮不做代理池 |
| 纯 HTTP 自动收割（免 App） | ⚠️ 部分 | `/api/device/` 已可自造；`/api/server/short/A/` 的 `key`/`appSign` 语义未破（见下） |
| App 缓存直取刷新（免 Frida/免 MITM） | ✅ 已验证 | `harvest_adb.py` 从 Room `swan_cache2` 拉出 141 节点（111 VL-R + 30 IK2）+ clientKey 并全部解密；**触发新拉取需 App 走到主界面（2 次点击）** |
| 合规判定 | ⛔ 不可直接商用 | 节点为 HaloVPN 自营 VPS（`sec0org/tapbykiwi` 系域名），凭证≠授权 |

## 快速开始

```bash
# 1) 解包 / 反编译（已产出）
#    apk_x/  ├─ assets/{ik_cache.json,vl_cache.json,key_cache.json}  内置兜底节点 + 密钥缓存
#    jadx_out/  17997 类反编译结果

# 2) 解析已经抓到的节点池（本目录已含捕获产物）
python harvest.py --count 2          # 走采集协议（见文档“自动收割现状”）
python gen_xray.py --alive "<ip1,ip2,...>" --out xray_alive.json
xray.exe -c xray_alive.json          # 起 38 个 socks：127.0.0.1:31000..31037

# 3) 真实拨测 + 吞吐
python probe.py --map xray_map.json --workers 12 --timeout 10
python speedtest.py --workers 6

# 4) demo（页面 + 订阅 + proxies.txt）
python demo_server.py --port 8940
# http://127.0.0.1:8940/        节点表（存活/出口IP/延迟）
# http://127.0.0.1:8940/proxies.txt   socks5 清单（new-api 直接读）
# http://127.0.0.1:8940/sub           vless 订阅（base64）
# http://127.0.0.1:8940/sub/clash     Clash/mihomo YAML
```

## 实测数据（2026-10-29，中国出口，直连拨测）

| 指标 | 值 |
|------|-----|
| 下发节点 | 144（VL-R 114 / IK2 30），32 国 |
| VL-R 存活（一轮） | **39 / 114**（34%） |
| 双轮稳定 | **38 / 39**（1 个抖动，双阈值策略下保留观察） |
| 存活国家数 | 24（US×7、GB×3、DE/BR/IL/AU/MY/KR 各 2，其余 1） |
| 唯一出口 IP | **38**（节点即出口，非隧道二次 NAT） |
| TTFB | P50 **840 ms**，P95 1447 ms，min 386 ms |
| 单流吞吐 | P50 **2.14 Mbps**，max 2.88 Mbps（36/38 有效） |
| 4 并发聚合 | **9.7 – 10.9 Mbps**（同节点），说明不是账号带宽封顶，而是单连接窗口限制 |
| 死节点特征 | 11/15 抽样 TCP SYN 可达但 TLS ClientHello 后 RST；RST 延迟≈1 RTT ⇒ 服务端 Reality 拒绝或对端服务下线 |

> Xray 侧开启 `mux`（concurrency 8）后链路直接变成 **0 字节**（Vision+REALITY 与 mux 不兼容），
> 已回退。要更高单流吞吐只能靠多连接聚合或多节点分流。

## 目录

```
apk_x/                    APK 解包（libswan.so、assets 内置缓存）
jadx_out/                 jadx 反编译源码
jadx_res/                 资源解码（含 remote_config_defaults.xml）
capture.jsonl             mitmproxy 抓包（含一次完整节点列表响应）
nodes_raw.json            原始节点响应（字段仍加密）
nodes_decrypted.json      144 节点全解密（凭证类，勿入库/勿外传）
xray_nodes.json           114 节点全量 Xray 配置
xray_alive.json           38 节点稳定集 Xray 配置（交付用）
xray_map.json             socks 端口 ↔ 节点映射
probe_result.json         全量一轮拨测
probe_round3.json         存活集复测
probe_final.json          最终集拨测（38/38）
speed_result.json         吞吐实测
harvest.py                协议客户端 / 收割器（HTTP 版）
harvest_adb.py            App 缓存直取刷新（模拟器 Room 库 → 解密，免 Frida/免 MITM）
gen_xray.py               Xray 配置生成
probe.py                  真实拨测（自建 SOCKS5 客户端，不走系统代理）
speedtest.py              吞吐测试
demo_server.py            页面 + 订阅 + proxies.txt（:8940）
hook_params.js            Frida 钩子（RSA/AES 明文观测，已实测可用）
docs/                     逆向报告 / 协议手册 / new-api 对接
```

## 路线图

1. ~~协议还原 + 节点池收割~~ ✅
2. ~~VLESS-REALITY 建链与压测~~ ✅
3. **免 App 全自动收割**：`/api/server/short/A/` 的 `key`/`appSign` 语义未破（App 侧 RSA 明文未落地），
   当前用「模拟器 + mitm 抓取」兜底（`hook_params.js` 已能钩到 `v2`/`v3` 明文，Frida 16.5.9 可稳定附着）
4. 转换层部署（VPS 侧 xray + socks，供线上 new-api 用）→ 见 `docs/NEWAPI_INTEGRATION.md`
5. 刷新链：`python harvest_adb.py --no-force`（App 有缓存时）或手点 App 主界面让它在拉一次，再跑同命令；
   `--reinstall` 能强制全量拉取，但本轮在 3 GB AVD 上仍未等到 App 自己走到主界面（ElaMods 首启弹窗拦截），标 partial
5. IK2 节点（30 条 IKEv2，PSK 已解出：`PSK*********AUTH`）→ 若需要可作为备份池

## 合规声明

- 本项目仅用于**协议与实现层面的安全研究**，验证「商业 VPN 客户端配置下发是否可被第三方复现」。
- 节点服务器为 HaloVPN 运营商自有基础设施（`*.sec0org.com` / `*.tapbykiwi.com` / `*.tapbypitaya.com` 系），
  **凭证可解密 ≠ 获得授权**。长期把他人付费节点接入自有生产代理池属于盗用基础设施，风险自负。
- 本仓库**不内置**任何可用凭证：`nodes_decrypted.json` / `xray_*.json` / `proxies*.txt` 已在 `.gitignore` 中排除，
  文档中出现的一切凭证均已脱敏。
