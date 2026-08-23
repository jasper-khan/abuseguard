# AbuseGuard

[English](README.en.md) | **简体中文**

AbuseGuard 是一个面向 Debian/Ubuntu 上 [Caddy](https://caddyserver.com/) 反向代理的即插即用滥用缓解层。它在防火墙层（nftables）封禁滥用及已知恶意 IP，并可选地将其自动上报到 [AbuseIPDB](https://www.abuseipdb.com/) —— 由 fail2ban 加一个小型 Go 引擎驱动。

一条命令即可装好：加固版 Caddy（内置 `caddy-dns/cloudflare` TLS 模块）、fail2ban jail、威胁情报同步、可选上报器，以及交互式 `abuseguard` 控制面板。

## 工作原理

```
访客 ─▶ Caddy（受保护站点：`import abuseguard`）
             │  写入隐私精简的 JSON 访问日志
             ▼
         fail2ban ──(命中)──▶ nftables DROP :80/:443   ← 封禁
             │
             └─(限速/探测)─▶ 引擎入队 ─▶ 上报队列 ──(定时器)──▶ AbuseIPDB
```

- Caddy 为每个到受保护站点的请求打标签，只记录 fail2ban 所需的字段（客户端 IP、协议、标签）——不记录路径、主机名、请求头或查询串。
- fail2ban 针对该日志运行四个 jail；封禁由 nftables 执行（对 tcp/80+443 丢弃）。
- 一个 Go 引擎（仅用标准库、单个静态二进制）负责封禁/放行判定、保持威胁情报名单新鲜、并冲刷上报队列。

## 环境要求

- Debian 11/12 或 Ubuntu 20.04+（amd64 或 arm64），需 root（sudo）。
- 适用于位于边缘代理（如 Cloudflare）之后的公网服务器。AbuseGuard 封禁/上报的是**真实客户端 IP**，因此 `trusted_proxies` 必须配置正确。

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

安装器是幂等的：已有的 config、whitelist、key 和 Caddyfile 都不会被覆盖。

安装过程中会**交互询问**两个可选密钥 —— Cloudflare API token（用 DNS-01 签发 TLS 证书）和 AbuseIPDB API key（用于自动上报）。**直接回车即可跳过**，两者都能之后随时在面板里设置。装完终端会醒目显示进面板的命令：

```bash
abuseguard
```

> 在无终端的环境（CI / nohup / 管道）里，安装会自动跳过询问；也可显式设 `ABUSEGUARD_NONINTERACTIVE=1` 强制跳过。
>
> 设置 `ABUSEGUARD_REPO=you/abuseguard` 可从你自己的 fork 安装。

### 网络慢 / 大陆镜像

安装器的 GitHub 下载（仓库 tarball + 引擎二进制）会**先尝试直连**，仅当直连卡住时，才自动依次经过一串公共 GitHub 代理，直到某个成功为止 —— 因此那条朴素的一行命令在海外（直连）和大陆（自动代理）都能用，无需任何参数。

若你的网络已知被墙，想跳过直连尝试，可设置 `ABUSEGUARD_MIRROR=cn` —— 它会直接走代理链，并把威胁情报名单指向 Fastly 的 jsDelivr CDN：

```bash
sudo ABUSEGUARD_MIRROR=cn ./install.sh          # 直接走代理链
sudo ABUSEGUARD_MIRROR=https://your.proxy/ ./install.sh   # 强制使用某个代理
```

`abuseguard` 面板的更新/卸载会沿用安装时设定的 `ABUSEGUARD_MIRROR`。Caddy 定制构建（`caddyserver.com`）不走代理；若它很慢，可在运行前先装好一个已内置 `caddy-dns/cloudflare` 模块的 Caddy（例如用 `xcaddy`）—— 安装器会检测到并保留它。

## 控制面板

直接运行 `abuseguard`（面板需要 root；以普通用户运行会自动通过 sudo 提权，必要时提示输入密码）：

- 查看服务、jail、定时器的状态
- 按 jail 列出当前被封禁的 IP
- 编辑白名单（会重载 fail2ban）
- 立即同步威胁情报 / 立即冲刷上报队列
- 设置 AbuseIPDB key / Cloudflare token
- 开关 AbuseIPDB 上报
- 查看近期日志、更新、卸载

## 防护模型

| Jail | 触发条件 | 阈值 | 封禁对象 |
| --- | --- | --- | --- |
| `caddy-intel` | 对受保护站点的任意请求 | 命中 1 次 | 仅威胁情报名单上的 IP |
| `caddy-rate-local` | 对受保护站点的任意请求 | 60 秒内 30 次 | 任意非白名单 IP + 加入上报队列 |
| `caddy-probe-h1` | 用 HTTP/1.1 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |
| `caddy-probe-h2` | 用 HTTP/2 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |

封禁时长为 90 天。白名单 IP（`/etc/caddy-abuseguard/whitelist`）永不封禁、永不上报。「敏感路径」= `/.env`、`/.git`、`/phpmyadmin`、`/vendor/phpunit`、`/cgi-bin`（及其子路径）。

## 威胁情报

在名单同步之前，intel jail 不封禁任何人。引擎会拉取一份公开的、源自 AbuseIPDB 的封禁名单，并拒绝加载明显异常偏小（<9 万）或偏大（>12 万）的名单；任何失败都会保留上一次的名单。刷新每 6 小时执行一次（也可通过面板手动触发）。

## AbuseIPDB 上报（可选）

配置里上报默认开启，但在你设置 API key（面板 → 6）之前不会做任何事。上报是隐私安全的（不含主机名/路径/请求头）、按 IP 去重（15 分钟窗口）、并有上限（每天 1000 条）。冲刷每 10 分钟执行一次。要彻底关闭，用面板 → 8。

## 接入你的站点

在 `/etc/caddy/Caddyfile` 的每个站点块里加入 `import abuseguard`：

```caddyfile
example.com {
	import abuseguard
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	reverse_proxy localhost:3000
}
```

然后 `sudo systemctl reload caddy`。片段只需改一处 —— 每个受保护站点都会跟随生效。

## 文件位置

```
/usr/local/bin/caddy                          Caddy（内置 caddy-dns/cloudflare）
/usr/local/bin/abuseguard                     控制面板
/usr/local/libexec/caddy-abuseguard           Go 引擎
/etc/caddy/Caddyfile                          你的站点
/etc/caddy/abuseguard.caddy                   (abuseguard) 片段
/etc/caddy-abuseguard/config.json             引擎配置
/etc/caddy-abuseguard/whitelist               永不封禁名单
/etc/caddy-abuseguard/abuseipdb-report.key    AbuseIPDB key（可选）
/var/lib/caddy-abuseguard/                     情报名单 + 上报队列/状态
/var/log/caddy/abuseguard-access.json         隐私精简的访问日志
```

## 更新 / 卸载

```bash
abuseguard                 # → 10 更新，→ 11 卸载
sudo ./uninstall.sh             # 删除程序文件，保留配置/状态
sudo ./uninstall.sh --purge     # 连配置、白名单、状态、日志一并删除
sudo ./uninstall.sh --dry-run   # 只打印将删除什么，不做任何改动
```

卸载会保留 Caddy 二进制、服务账户，以及已有的 nft 封禁规则。

## 安全须知

- Caddy 本身不提供任何鉴权。凡是你对外暴露的站点，除非你自己加了鉴权，否则都是公开的。
- 安装器的自检站点只绑定 `127.0.0.1:8080`。
- 密钥（`*.key`、`.env`）权限为 0640 且已被 git 忽略；切勿提交。

## 构建 / 发布

- `engine/` 是单个 Go module，仅用标准库，`go 1.21`。
- 打 `vX.Y.Z` 标签会触发 [`.github/workflows/release.yml`](.github/workflows/release.yml)，它构建 `caddy-abuseguard-linux-{amd64,arm64}` 并附加到 release。`install.sh` 默认下载这些产物。

架构与「失败即安全」规则详见 [docs/design.md](docs/design.md)。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
