# HaloVPN v17.4.0 逆向报告

- APK：`HaloVPN v17.4.0 b170400 (Premium by @ElaMods).apk`，98 373 354 B，arm64-v8a + armeabi-v7a
- 包名：`com.thehot.halovpnpro`；versionName `17.4.0` / versionCode `170400`
- 分析日期：2026-10-29；环境：Windows 10 + Android 11 x86_64 AVD（ndk_translation）+ jadx + Frida 16.5.9 + mitmproxy 12

## 1. 架构判定

| 组件 | 证据 | 结论 |
|------|------|------|
| v2rayNG 内核 | `libgojni.so`、`com.v2ray.ang.*`、`XrayConfigUtils`、`AngConfig$VmessBean` | 客户端 = v2rayNG 改皮，内核 Xray（Go） |
| 通道 | `libhev-socks5-tunnel.so` | TUN→SOCKS5 转发，规则走 Xray inbound |
| IKEv2 | `libstrongswan.so / libcharon.so / libipsec.so`、`org.strongswan.android.*` | 第二条链路：IKEv1/IKEv2（证书或 PSK） |
| 混淆壳 | `libswan.so`（`SignUtils` JNI：`getDData/getEData/getPublicKey/getSign/getTXT`） | 密钥材料 + 签名都在 native |
| 业务壳 | `q6.e`（Firebase RemoteConfig 封装，控制流平坦化）、`q6.m`（节点管理器）、`q6.o`（偏好/解密管线） | 大量 `switch(str.hashCode()^K)` 垃圾分支 |

APK 里没有 Flutter（无 `libapp.so`），是「Java/Kotlin 业务 + Go 内核 + native 密钥库」的组合。

## 2. 数据流（节点从哪来）

```
启动 ──► SplashActivity ──► /api/domain/remote（taptoboy，零鉴权）
                              │  serverDomain / vlCountry / tCountry / preServer / dServer
                              ▼
                     /api/device/（注册/取额度，accountType=free|vip）
                              ▼
     /api/server/short/A/（144 条节点，字段 RSA+AES 加密）──┐
                              │                            │
       FirebaseRemoteConfig: fix_cache / fix_cache_vl      │ 兜底
                              ▼                            ▼
             Room 缓存（CacheBean：f28242e=节点JSON, f28243f=clientKey）
                              ▼
               HaloServerShort.parseServer() → HaloServer
                              ▼
       q6.o.h(server, SignUtils.getDData(clientKey))  ← AES 解 p/px/pik/po/psk/ssid
                              ▼
        XrayConfigUtils 生成 outbound（vless+reality / vmess / hy2 …）
                              ▼
        hev-socks5-tunnel ← gojni(Xray) ──► TUN
```

关键点：

- 缓存兜底用的是 APK 内置 `assets/vl_cache.json` + `assets/key_cache.json`（`v7.t.p()` 直接读 assets），
  所以**离线也能拿到 20 条 free 节点**。
- `FirebaseRemoteConfig.getString("fix_cache")`（IKE 池）/ `"fix_cache_vl"`（VLESS 池）是**节点 JSON 的云端副本**，
  与 `/api/server/short/A/` 同结构；`server_host_url` 决定首选 host。
- `q6.e` 全类被控制流平坦化（`while(true) switch(str.hashCode()^const)`），jadx 大面积 `Code decompiled incorrectly`，
  但它只是 RC getter，真实键名在字符串表里明文可见。

## 3. 加密体系（三层，全部还原）

| 层 | 算法 | 密钥 | 位置 |
|----|------|------|------|
| 接口签名 | MD5(盐 + 排序 k=v + 盐) | `halo*^%)vpn&^$!@+halo` | `v7.d0.a/b` |
| 请求参数 `key`/`appSign` | RSA/None/PKCS1Padding（公钥加密） | `SWAN_PUBLIC_KEY` | `libswan.so`（只给公钥，私钥在服务端） |
| 响应 `key` → 会话密钥 | RSA/None/PKCS1Padding（私钥解密） | `INSIDE_PRIVATE_KEY`（PKCS#8 1024-bit） | `libswan.so` 明文 base64 |
| 节点字段 | AES-128-CBC/PKCS5 | 会话密钥（16 字符） | IV `myhalovpnbestvpn`，`v7.a.a()` |

- `SignUtils.getDData(clientKey)`：native，作用 = 用 INSIDE 私钥解 128 字节密文 → 16 字符会话密钥（Frida 实测：
  `QoeEaRl...118=` → `1sFq4na8JU7p1X56`）。
- `SignUtils.getEData(x)`：native，作用 = 用 SWAN 公钥加密（购买凭证 `p=<product>&es=<到期毫秒>`，见 `j7.a:63`）。
- `EncryptedPrivateKey`/`PKCS8` 全部可离线复现，无需模拟器（本轮 144 条全解成功）。

## 4. 节点池画像（本轮下发快照）

| 维度 | 数据 |
|------|------|
| 总量 | 144 条，32 国 |
| 协议 | `VL-R`(VLESS+REALITY+tcp+Vision) 114 条（全部 `st=vip`）；`IK2`(IKEv2) 30 条（`st=free`） |
| 域名家族 | `*.sec0org.com` / `*.sec6org.com` / `*.sec17org.com` / `*.tapbykiwi.com` / `*.tapbypitaya.com` / `*.tapby...`，形如 `origin-<8hex>.sec0org.com`、`<12位数字>.sec6org.com` |
| 服务商痕迹 | 大量 AS 分散（OVH / Hetzner / Oracle / AWS / LightNode / Vultr 等），`sn` 命名 `国家-城市-编号`（如 `RO-BUH-8745`） |
| 端口 | reality 统一 443（`spr`），IKE 4500/443 |
| 出口 | `oip == sip`（38 个存活样本 100% 相符）⇒ 节点即出口，没有二次 NAT，适合当代理出口 |

## 5. 存活与性能（中国出口，直连拨测）

- 一轮：**39 / 114** VL-R 真实握手存活（34%）
- 二轮（存活集）：**38 / 39**；三轮：38/38 ⇒ 稳定集 38
- TTFB P50 840 ms / P95 1447 ms（RTT 基线 190–400 ms，reality 握手 2×RTT + 应用 RTT）
- 单流 P50 2.14 Mbps，max 2.88 Mbps；同节点 4 并发聚合 9.7–10.9 Mbps ⇒ 单连接窗口限制，不是账号带宽封顶
- 死节点：11/15 抽样 TCP SYN 可达，TLS ClientHello 后 ~1 RTT 收到 RST。
  两种解释：(a) 服务端 reality 校验失败后回落目标域不可达；(b) 该 IP/SNI 组合在链路上被注入 RST。
  由于**存活节点同族域名同样随机**，倾向 (a) —— 即这批节点本身服务端配置失效或已下线（运营商不清理死节点）。
- `st=vip` **没有被服务端拦截**：114 条 vip 节点里 38 条对 free 设备返回了可用凭证并建链成功
  ⇒ App 侧的“VIP 才能点”是纯客户端限制。

## 6. 未破点（诚实记录）

1. **请求 `key` / `appSign` 的真实明文未落地**：两者都是 RSA-1024 密文（172 字符 base64），
   用 `SWAN` 公钥加密、服务端持有私钥；抓包原样重放（连 `time` 都不改）仍返回
   `{"code":400,"msg":"unknown exception"}`，说明服务端做了**一次性/时效**校验，而不只是参数正确性。
   已备好 Frida 钩子（`hook_params.js` 钩 `RSAUtils.encryptedDataOnJava` / `SignUtils.getEData`），
   在模拟器稳定时可一次落地 —— 落地后即可 100% 免 App 自动收割。
2. **`/api/server/short/A/` 的 `serverCountry` 语义**：抓包里是空串，改成具体国家码是否会改变下发集合未验证。
3. **IK2 的 30 条节点未建链**：需要 strongSwan（`pik` 账号 + `psk` 预共享密钥已解出），
   本轮聚焦 SOCKS 代理池，未做 IKE 隧道验证。

## 7. 踩坑清单（可直接复用）

1. `pm install` 直接装 98 MB APK 会 `Broken pipe` → `adb push` + `pm install -r -g /data/local/tmp/x.apk`。
2. AVD 只有 3 GB 内存，`pm clear` 后立刻 `frida spawn` 常 `DeadSystemException` / spawn 超时；
   `attach` 到已运行进程更稳，且 Frida 16.5.9 与 `frida-server-android`(17.24.3) 版本必须成对。
3. mitmproxy 抓 Google/Firebase 必须 `--mode upstream:http://127.0.0.1:10808`，
   否则 CONNECT 全部 502；抓节点池（`tapto*`）同样需要境外出口。
4. jadx 6 个 dex 全量约 6 分钟（17997 类，99 个类失败），只解资源用 `--no-src` 更快。
5. 反混淆类一律以「字符串表 + 常量类」为准，别指望 jadx 把 `q6.e` 还原成可读代码。

## 8. 合规判定

- 节点是 HaloVPN 自营基础设施；凭证可解 ≠ 有使用权。**生产代理池接入属盗用第三方基础设施**，
  本项目只作为协议研究与本地验证证据，交付物不内置可用凭证（`.gitignore` 已排除）。
