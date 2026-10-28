# 接入 new-api 代理池

> 目标：把 HaloVPN 的 38 条 VLESS-REALITY 节点变成 new-api 可用的 SOCKS5 出口。
> 前提事实（已核对 `relay/channel/tryingopen/proxy_pool.go` 源码）：**new-api 业务代码不用改一行**。

## 1. new-api 侧的现状（静态确认）

| 事实 | 位置 | 影响 |
|------|------|------|
| `TRYINGOPEN_PROXY_FILE` 支持**逗号分隔多文件** | `LoadProxies()` / `proxy_pool.go:381` | 可以和现有住宅/免费清单并存 |
| 每行 `socks5://host:port`，`#` 开头跳过 | 同上 | 转换层直接吐端口清单即可 |
| 住宅源加载后 `source="residential"`、`healthScore=1.0`（池内最高权重） | 同上 | 立刻进入高权重 |
| `TraceProbes()` 里 `if e.source != "free" { continue }` | `proxy_pool.go:1159+` | **住宅清单不会被平台拨测**，出口正确性必须由转换层自己保证 |
| 同一代理连续失败 5 次 → 10 分钟全局熔断 | `globalFailThreshold` | 隧道抖动会表现为“整池突然全挂”，转换层要保证 fail-closed |
| 429 冷却按 24h 内使用次数递增（0/30/90/300/900s） | 源码头注释 | 端口少时整池易冷却 → 建议 ≥30 个端口 |

## 2. 架构（推荐：一台境外 VPS 当转换层）

```
new-api (线上)
   │  渠道/出站：socks5://<vps>:31xxx
   ▼
转换层 VPS（Linux，4C2G 足够）
   ├─ xray -c xray_alive.json        38 个 socks inbound（127.0.0.1:31000..31037）
   │    每 inbound 绑定一个 vless+reality outbound（Vision, fp=chrome）
   ├─ 健康任务：每 5min 跑 probe，双阈值剔除（连续 2 轮失败才摘）
   └─ proxies.txt  →  new-api 读同一份清单
```

为什么不放本机：本轮 38 个 socks 端口绑在 `127.0.0.1`，new-api 若在容器/别的机器里就够不着；
放 VPS 后只需把 socks 监听从 `127.0.0.1` 改成 `0.0.0.0`（**务必用防火墙限定来源 IP**，SOCKS 无认证＝裸奔）。

## 3. 落地步骤（VPS 侧）

```bash
# 1) 装 xray（26.x 已验证可用）
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 2) 放配置（把 inbounds 的 listen 改成 0.0.0.0）
python3 gen_xray.py --alive "<存活 sip 列表>" --out /usr/local/etc/xray/halo.json
sed -i 's/"listen": "127.0.0.1"/"listen": "0.0.0.0"/' /usr/local/etc/xray/halo.json
systemctl restart xray

# 3) 生成清单（new-api 直接读）
python3 - <<'PY'
import json
m=json.load(open('xray_map.json'))
open('/etc/newapi/halo_proxies.txt','w').write(
    "".join(f"socks5://<vps_ip>:{x['port']}\\n" for x in m))
PY

# 4) 健康检查（每 5 分钟，双阈值）
*/5 * * * * cd /opt/halo && python3 probe.py --map xray_map.json --out probe_final.json && python3 subgen.py
```

`subgen.py` 逻辑：读出 `probe_final.json`，连续两轮 `alive=false` 的端口从 `halo_proxies.txt` 摘掉，
新存活端口补回；写文件用「临时文件 + rename」避免 new-api 读到半个文件。

## 4. new-api 侧配置

```dotenv
# 两个文件逗号分隔：住宅清单 + 本地协议转换层
TRYINGOPEN_PROXY_FILE=/etc/newapi/residential_proxies.txt,/etc/newapi/halo_proxies.txt
```

- 容器部署时 `127.0.0.1` 是**容器自己的 loopback**，三选一：
  ① `extra_hosts: host.docker.internal:host-gateway` + 端口绑 `0.0.0.0`；② `network_mode: host`；③ 转换层与 new-api 同 compose 网络。
- 重启后到 `/api/twoapi/proxy_pool` 应能看到 `socks5://<vps>:31xxx` 条目（`source=residential`、`healthScore=1.0`）。

## 5. 三层验收（缺一不算通）

| 层 | 动作 | 期望 |
|----|------|------|
| 隧道层 | `curl --socks5-hostname <vps>:31000 https://api.ipify.org` | 返回节点真实出口 IP（== 该节点 `sip`） |
| 池层 | `/api/twoapi/proxy_pool` | 出现 38 条 socks 条目，`residential` |
| 业务层 | 走该渠道发一次真实上游请求 | 上游侧看到的来源 IP == 节点出口 IP |

## 6. 关键风险

1. **合规**：节点是 HaloVPN 自营 VPS，凭证≠授权。生产使用属盗用第三方基础设施，运营方自担风险；
   若要长期稳定，正解是「自建 VPS + Xray」而不是薅别人节点。
2. **节点会轮换/下线**：本轮 66% 的 VL-R 一开始就握手失败；上游不清理死节点 ⇒ 必须自建测活 + 双阈值摘除。
3. **凭证刷新**：`/api/server/short/A/` 的 `key`/`appSign` 尚未能自造（见 `REVERSE_REPORT.md` 第 6 节），
   当前刷新靠「模拟器 + mitm 抓一次」，一次抓包得到 24h 有效的新池子；`server_nodes_cache_duration=86400`。
4. **单流 2 Mbps**：适合 Chat/API 类小请求，不适合大文件下载。并发聚合可达 10 Mbps。
5. **SOCKS 无认证**：VPS 上必须用安全组/`iptables` 限定只允许 new-api 出口 IP 访问 31xxx 端口段。


## 7. 给对接会话的开场指令（可直接复制）

```
读 C:/Users/Administrator.DESKTOP-EGNE9ND/Desktop/逆向产物/HaloVPN_17.4.0/docs/NEWAPI_INTEGRATION.md
和同目录 docs/PROTOCOL.md，按文档把 HaloVPN 的 socks 池接进 new-api 代理池。
约束：不改 new-api 业务代码；只通过 TRYINGOPEN_PROXY_FILE 挂清单；
先本机验证（xray_alive.json + probes.txt），再决定是否上 VPS；
验收必须三层：隧道层出口 IP == 节点 sip、池层 /api/twoapi/proxy_pool 有条目、业务层上游看到节点出口 IP。
```

## 8. 交接清单（对面会话需要拿到什么）

| 需要 | 从哪拿 |
|------|--------|
| 38 条节点配置 | `xray_alive.json`（含 reality 公钥/shortId/UUID，**敏感**） |
| socks 端口映射 | `xray_map.json` |
| 可直接读的清单 | `proxies_alive.txt`（或 `http://<转换层>:8940/proxies.txt`） |
| 刷新命令 | `python harvest_adb.py --no-force`（App 有缓存时）/ 手点 App 再跑 |
| 测活命令 | `python probe.py --map xray_map.json` |
| 生命周期 | 节点池每 24h 变一次（`server_nodes_cache_duration=86400`）；建议 5 min 一轮测活 + 双阈值摘除 |
