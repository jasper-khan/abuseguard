# AbuseGuard

[English](README.en.md) | **简体中文**

AbuseGuard 是一个面向 Debian/Ubuntu 上 [Caddy](https://caddyserver.com/) 反向代理的即插即用滥用缓解层。它对直接到达源站的连接在防火墙层（nftables）封禁滥用及已知恶意 IP，并可选地将其自动上报到 [AbuseIPDB](https://www.abuseipdb.com/) —— 由 fail2ban 加一个小型 Go 引擎驱动。

一条命令即可装好：加固版 Caddy（内置 `caddy-dns/cloudflare` TLS 模块）、fail2ban jail、威胁情报同步、可选上报器，以及交互式 `abuseguard` 控制面板。

## 工作原理

```
访客 ─▶ Caddy（受保护站点：`import abuseguard`）
             │  写入隐私精简的 JSON 访问日志
             ▼
         fail2ban ──(命中)──▶ nftables DROP :80/:443   ← 直连源站封禁
             │
             └─(敏感路径探测)─▶ 引擎入队 ─▶ 上报队列 ──(定时器)──▶ AbuseIPDB
```

- Caddy 为每个到受保护站点的请求打标签，只记录 fail2ban 所需的字段（客户端 IP、协议、标签）——不记录路径、主机名、请求头或查询串。
- fail2ban 针对该日志运行四个 jail；直连源站的封禁由 nftables 执行（对 tcp/80+443 丢弃）。
- 一个 Go 引擎（仅用标准库、单个静态二进制）负责封禁/放行判定、保持威胁情报名单新鲜、并冲刷上报队列。

## 环境要求

- Debian 11/12 或 Ubuntu 20.04+（amd64 或 arm64），需 root（sudo）。
- nftables 封禁适用于客户端直接连接源站（包括 Cloudflare DNS-only）的站点。

## 安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jasper-khan/abuseguard/main/install.sh)
```

或克隆后运行：

```bash
git clone https://github.com/jasper-khan/abuseguard
cd abuseguard
sudo ./install.sh                 # 从最新 release 下载预编译引擎
sudo ./install.sh --from-source   # 或在本地用 Go 编译引擎（需要 go）
```

安装器是幂等的：已有的 config、whitelist、key 和无关 Caddy 配置都会保留。旧版或手工写在主 Caddyfile 中的 AbuseGuard 受保护站点，会迁移为标准的 `/etc/caddy/sites/<域名>.caddy`，站点内统一使用 `import abuseguard`；迁移后的完整配置必须校验通过才会生效。

安装器会自动补齐 `fail2ban`、`rsyslog`、`nftables` 等运行依赖；`rsyslog` 为 Debian/Ubuntu 默认的 `sshd` jail 提供 `/var/log/auth.log`，AbuseGuard 的网站防护仍使用独立的 Caddy JSON 日志。已有 Caddy 服务中的 Cloudflare token 会安全写入 AbuseGuard 的 `/etc/caddy/.env`，不会在终端显示。

首次安装会**交互询问**两个可选密钥 —— Cloudflare API token（用 DNS-01 签发 TLS 证书）和 AbuseIPDB API key（用于自动上报）。**直接回车即可跳过**，AbuseIPDB key 输入时不会回显；两者都能之后随时在面板里设置。更新时会保留现有密钥、跳过这些询问，并在成功后自动重新加载面板。装完终端会醒目显示进面板的命令：

```bash
abuseguard
```

> 在无终端的环境（CI / nohup / 管道）里，安装会自动跳过询问；也可显式设 `ABUSEGUARD_NONINTERACTIVE=1` 强制跳过。
>
> 设置 `ABUSEGUARD_REPO=you/abuseguard` 可从你自己的 fork 安装。

### 网络慢 / 大陆镜像

安装器的 GitHub 下载（仓库 tarball、引擎、以及带 cloudflare 模块的 Caddy）会**先尝试直连**，仅当直连卡住时，才自动依次经过一串公共 GitHub 代理，直到某个成功为止 —— 因此那条朴素的一行命令在海外（直连）和大陆（自动代理）都能用，无需任何参数。

若你的网络已知被墙，想跳过直连尝试，可设置 `ABUSEGUARD_MIRROR=cn` —— 它会直接走代理链，并把威胁情报名单指向 Fastly 的 jsDelivr CDN：

```bash
sudo ABUSEGUARD_MIRROR=cn ./install.sh          # 直接走代理链
sudo ABUSEGUARD_MIRROR=https://your.proxy/ ./install.sh   # 强制使用某个代理
```

引擎和带 cloudflare 模块的 Caddy 都从本仓库的 GitHub release 下载（Caddy 由 CI 用 `xcaddy` 构建），因此都享受上面的直连→镜像回退，大陆无需额外配置。`abuseguard` 面板的更新/卸载会沿用安装时设定的 `ABUSEGUARD_MIRROR`。若系统已存在带 `caddy-dns/cloudflare` 模块的 Caddy，安装器会自动检测并保留、跳过下载。

**完整性校验（强制）**：下载的 engine 与 Caddy **必须**通过 release 里 `SHA256SUMS.txt` 的校验。校验文件体积极小，因此会尽力拿到：先直连 GitHub（被限速也能拿到），失败再走整条镜像链，并带重试。**校验不符、或校验文件就是拿不到，都会中止安装**（不会“跳过校验继续装”）；如遇网络问题，请重试或用 `--from-source` 本地编译。诚实说明边界：若你用 `ABUSEGUARD_MIRROR=<prefix>/` 强制单一镜像，校验文件也会走该镜像，此时只能防"被动缓存型"镜像、防不住对该线路的主动篡改。

**Cloudflare IP 段兜底**：生成 Caddyfile 时会拉取 Cloudflare 的 IP 段填入 `trusted_proxies`；若网络受限拉取失败，会退回内置快照（`assets/caddy/cloudflare-ips.fallback`），避免 `trusted_proxies` 只剩回环——那会让 Caddy 把所有访客都当成 Cloudflare 边缘 IP，进而封禁 Cloudflare 自身、导致整站不可用。

**已有 Caddy 迁移**：若安装前已有 Caddyfile，安装器会先备份原文件，再把其中可明确识别的“单一公网域名 + `reverse_proxy`”站点完整迁入 `/etc/caddy/sites/<域名>.caddy`，并加入 `import abuseguard`。站点原有的 TLS、路由、请求头和上游配置均保留；全局块、snippet、IP/端口监听及非反代站点仍留在主 Caddyfile。迁移后的完整配置必须通过 Caddy 校验才会生效。

## 控制面板

直接运行 `abuseguard`（面板需要 root；以普通用户运行会自动通过 sudo 提权，必要时提示输入密码）。标题会显示当前 AbuseGuard 引擎版本：

- 查看状态：服务、**受保护域名**、jail、定时器、**情报最后同步时间**
- **站点/反代管理**：输入域名 + 上游（本地端口或远程 IP:端口）即自动生成受保护的反代站点（自动写入 `import abuseguard` + 按需 TLS），也可列出/删除
- 按 jail 列出当前被封禁的 IP
- **解封 / 立即封禁指定 IP**（误封可一键解封）
- 编辑白名单（面板内增删；**新增会自动解封该 IP** 并重载 fail2ban）
- 立即同步威胁情报 / 立即冲刷上报队列
- 设置 AbuseIPDB key / Cloudflare token
- 开关 AbuseIPDB 上报
- 查看近期日志、更新、卸载

更新会在校验前用 `caddy fmt` 规范化主 Caddyfile 和 `/etc/caddy/sites/*.caddy`，并删除 Caddy 明确判定为冗余的精确指令 `header_up X-Forwarded-Host {host}` 或 `header_up X-Forwarded-Host {http.request.host}`；其他反代配置和请求头均保留。

## 防护模型

| Jail | 触发条件 | 阈值 | 封禁对象 |
| --- | --- | --- | --- |
| `caddy-intel` | 对受保护站点的任意请求 | 命中 1 次 | 仅威胁情报名单上的 IP |
| `caddy-rate-local` | 对受保护站点的任意请求 | 60 秒内 120 次 | 任意非白名单 IP（仅本地封禁） |
| `caddy-probe-h1` | 用 HTTP/1.1 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |
| `caddy-probe-h2` | 用 HTTP/2 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |

封禁时长为 90 天。白名单 IP（`/etc/caddy-abuseguard/whitelist`）永不封禁、永不上报。「敏感路径」= `/.env`、`/.git`、`/phpmyadmin`、`/vendor/phpunit`、`/cgi-bin`（及其子路径）。

## 威胁情报

在名单同步之前，intel jail 不封禁任何人。引擎会拉取一份公开的、源自 AbuseIPDB 的封禁名单，并拒绝加载明显异常偏小（<9 万）或偏大（>12 万）的名单；任何失败都会保留上一次的名单。刷新每 6 小时执行一次（也可通过面板手动触发）。

## AbuseIPDB 上报（可选）

配置里上报默认开启，但只有设置 API key 后，敏感路径探测事件才会入队并以 AbuseIPDB 类别 21 上报；普通请求速率只触发本地封禁。上报关闭或没有 key 时不会新增队列记录，且不影响 Fail2Ban/nftables 本地封禁和威胁情报同步。上报原因只包含实际次数、检测窗口和 HTTP 协议，不含主机名、路径或请求头；报告按 IP 去重（15 分钟窗口），每天最多 1000 条。冲刷时会先把当前队列原子轮转为独立批次，因此发送期间新入队的记录会留在新队列。白名单无法可靠读取或状态文件损坏时，冲刷会停止并返回失败；临时 API 故障保留记录重试。冲刷每 10 分钟执行一次。要关闭外部举报，用面板 → 11。

## 接入你的站点

每个受保护站点使用独立文件 `/etc/caddy/sites/<域名>.caddy`，并在站点块里加入 `import abuseguard`：

```caddyfile
example.com {
	import abuseguard
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	reverse_proxy localhost:3000
}
```

然后执行 `sudo systemctl reload caddy || sudo systemctl restart caddy`（关闭了 Caddy admin API 时会自动走重启）。主 `/etc/caddy/Caddyfile` 只保留全局配置及对 `abuseguard.caddy`、`sites/*.caddy` 的导入；片段只需改一处，每个受保护站点都会跟随生效。

示例里的 Cloudflare token 只用于 DNS-01 证书签发。

## 文件位置

```
/usr/local/bin/caddy                          Caddy（内置 caddy-dns/cloudflare）
/usr/local/bin/abuseguard                     控制面板
/usr/local/libexec/caddy-abuseguard           Go 引擎
/etc/caddy/Caddyfile                          全局配置 + AbuseGuard 导入
/etc/caddy/abuseguard.caddy                   (abuseguard) 片段
/etc/caddy/sites/<域名>.caddy                 每个受保护站点一个文件
/etc/caddy-abuseguard/config.json             引擎配置
/etc/caddy-abuseguard/whitelist               永不封禁名单
/etc/caddy-abuseguard/abuseipdb-report.key    AbuseIPDB key（可选）
/var/lib/caddy-abuseguard/                     情报名单 + 上报队列/状态
/var/log/caddy/abuseguard-access.json         隐私精简的访问日志
```

## 更新 / 卸载

```bash
abuseguard                       # 面板：[13] 更新、[14] 卸载
sudo ./uninstall.sh              # 交互选择：保守 / 彻底
sudo ./uninstall.sh --conservative   # 保守：删 AbuseGuard，保留 Caddy 和你的反代
sudo ./uninstall.sh --purge          # 彻底：按安装清单删 AbuseGuard 装的一切
sudo ./uninstall.sh --dry-run        # 只打印将删除什么，不做任何改动
```

卸载**对称于安装**：安装时会记录一份清单（哪些是 AbuseGuard 新建的、哪些你原本就有）。

- **保守卸载**：只删 AbuseGuard 组件，并从 Caddyfile 摘掉 AbuseGuard 的引入（`import abuseguard`、snippet、自检站点），**保留你原有的 Caddy、账户和反代配置**。
- **彻底卸载**：再按清单删 AbuseGuard 安装的 Caddy/账户/配置 —— 但**装之前你已有的一律不动**（原本就有 Caddy 就不会删 Caddy）。清单丢失时自动降级为最保守处理。
- `/etc/caddy/sites` 中由 AbuseGuard 管理的站点，卸载时可选「保留反代、只去防护」或「一起删」。原有 Caddyfile 在安装时已备份为 `Caddyfile.pre-abuseguard`。

## 安全须知

- Caddy 本身不提供任何鉴权。凡是你对外暴露的站点，除非你自己加了鉴权，否则都是公开的。
- 安装器的自检站点只绑定 `127.0.0.1:8080`。
- 密钥（`*.key`、`.env`）权限为 0640 且已被 git 忽略；切勿提交。
- 下载的二进制会用 `SHA256SUMS.txt` 校验（见「网络慢 / 大陆镜像」的完整性校验说明）。
- Caddy 以加固的 systemd 单元运行（`NoNewPrivileges`、`ProtectSystem=strict`、能力集限定、系统调用过滤等）；两个引擎定时任务同样加固。

## 构建 / 发布

- `engine/` 是单个 Go module，仅用标准库，`go 1.21`。
- 打 `vX.Y.Z` 标签会触发 [`.github/workflows/release.yml`](.github/workflows/release.yml)，它构建 `caddy-abuseguard-linux-{amd64,arm64}` 并附加到 release。`install.sh` 默认下载这些产物。
- 版本化的引擎产物发布后保持不变；每周/手动刷新只更新跟随上游的 Caddy，并重新生成覆盖全部现有产物的校验和与构建元数据。

架构与「失败即安全」规则详见 [docs/design.md](docs/design.md)。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
