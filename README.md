# AbuseGuard

[English](README.en.md) | **简体中文**

AbuseGuard 是一个面向 Debian/Ubuntu 上 [Caddy](https://caddyserver.com/) 反向代理的即插即用滥用缓解层。它对直接到达源站的连接在防火墙层（nftables）封禁滥用及已知恶意 IP，并可选地将其自动上报到 [AbuseIPDB](https://www.abuseipdb.com/) —— 由 fail2ban 加一个小型 Go 引擎驱动。

一条命令即可装好：加固版 Caddy（内置 `caddy-dns/cloudflare` TLS 模块）、nftables 入站防火墙、fail2ban jail、威胁情报同步、可选上报器，以及交互式 `ag` 控制面板。

## 工作原理

```
访客 ─▶ Caddy（受保护站点：`import abuseguard`）
             │  写入隐私精简的 JSON 访问日志
             ▼
         fail2ban ──(命中)──▶ nftables 按源 IP DROP 全部端口/协议
             │
             └─(敏感路径探测)─▶ 引擎入队 ─▶ 上报队列 ──(定时器)──▶ AbuseIPDB

sshd/auth.log ─▶ sshd / sshd-intel ──(认证爆破 / 情报命中)──▶ 同样的全入口封禁
```

- Caddy 为每个到受保护站点的请求打标签，只记录 fail2ban 所需的字段（客户端 IP、协议、标签）——不记录路径、主机名、请求头或查询串。
- 安装时启用四个 Web jail 和两个 SSH jail，共用白名单和威胁情报名单。任一 jail 封禁某个 IP 后，nftables 会拦截该源 IP 到本机所有端口、所有协议的流量，包括 SSH。
- 一个 Go 引擎（仅用标准库、单个静态二进制）负责封禁/放行判定、保持威胁情报名单新鲜、并冲刷上报队列。

## 环境要求

- Debian 11/12 或 Ubuntu 20.04+（amd64 或 arm64），需 root（sudo）。
- nftables 封禁适用于客户端直接连接源站（包括 Cloudflare DNS-only）的站点。

## 安装

安装器会检查六个 jail 的有效配置和启动状态。若旧的 `jail.local` 或 `jail.d/*.local` 禁用了其中某个 jail（例如 `[sshd] enabled = false`），安装会报错；请解除禁用冲突后重试。安装器不会自动改写这些自定义文件。

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

安装器是幂等的：已有的 config、whitelist、key 和无关 Caddy 配置都会保留。旧版或手工写在主 Caddyfile 中的 AbuseGuard 受保护站点，会迁移为标准的 `/etc/caddy/sites/<域名>.caddy`，站点内统一使用 `import abuseguard`；主配置、已有站点和防护片段先在候选副本上处理，完整配置通过校验后才替换正式文件，替换失败会回滚。

安装器会自动补齐 `fail2ban`、`rsyslog`、`nftables` 等运行依赖；`rsyslog` 为 Debian/Ubuntu 默认的 `sshd` jail 提供 `/var/log/auth.log`，AbuseGuard 的网站防护仍使用独立的 Caddy JSON 日志。已有 Caddy 服务中的 Cloudflare token 会安全写入 AbuseGuard 的 `/etc/caddy/.env`，不会在终端显示。

首次安装会**交互询问**两个可选密钥 —— Cloudflare API token（用 DNS-01 签发 TLS 证书）和 AbuseIPDB API key（用于自动上报）。**直接回车即可跳过**，AbuseIPDB key 输入时不会回显；两者都能之后随时在面板里设置。更新时会保留现有密钥、跳过这些询问，并在成功后自动重新加载面板。装完终端会醒目显示进面板的命令：

```bash
ag
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

引擎和带 cloudflare 模块的 Caddy 都从本仓库的 GitHub release 下载（Caddy 由 CI 用 `xcaddy` 构建），因此都享受上面的直连→镜像回退，大陆无需额外配置。`ag` 面板的更新/卸载会沿用安装时设定的 `ABUSEGUARD_MIRROR`。若系统已存在带 `caddy-dns/cloudflare` 模块的 Caddy，安装器会自动检测并保留、跳过下载。

**完整性校验（强制）**：下载的 engine 与 Caddy **必须**通过 release 里 `SHA256SUMS.txt` 的校验。校验文件体积极小，因此会尽力拿到：先直连 GitHub（被限速也能拿到），失败再走整条镜像链，并带重试。**校验不符、或校验文件就是拿不到，都会中止安装**（不会“跳过校验继续装”）；如遇网络问题，请重试或用 `--from-source` 本地编译。诚实说明边界：若你用 `ABUSEGUARD_MIRROR=<prefix>/` 强制单一镜像，校验文件也会走该镜像，此时只能防"被动缓存型"镜像、防不住对该线路的主动篡改。

**Cloudflare IP 段兜底**：生成 Caddyfile 时会拉取 Cloudflare 的 IP 段填入 `trusted_proxies`；若网络受限拉取失败，会退回内置快照（`assets/caddy/cloudflare-ips.fallback`），避免 `trusted_proxies` 只剩回环——那会让 Caddy 把所有访客都当成 Cloudflare 边缘 IP，进而封禁 Cloudflare 自身、导致整站不可用。

**已有 Caddy 迁移**：若安装前已有 Caddyfile，安装器会先备份原文件，再把其中可明确识别的“单一公网域名 + `reverse_proxy`”站点完整迁入 `/etc/caddy/sites/<域名>.caddy`，并加入 `import abuseguard`。站点原有的 TLS、路由、请求头和上游配置均保留；全局块、snippet、IP/端口监听及非反代站点仍留在主 Caddyfile。迁移后的完整配置必须通过 Caddy 校验才会生效。

## 控制面板

直接运行 `ag`（面板需要 root；以普通用户运行会自动通过 sudo 提权，必要时提示输入密码）。标题会显示当前 AbuseGuard 引擎版本，首页会显示当前 SSH 端口和受保护站点数；“当前封禁”每 30 分钟重新查询各 jail，无需进入菜单手动刷新：

面板使用 `=` 分隔线、左对齐的 `标签 : 值` 状态区和单列编号菜单；整个面板按终端宽度水平居中。首页显示防护结论、封禁数、情报库、上报状态、SSH 端口、站点数与版本，子页面沿用同一结构。状态值用颜色区分（绿=正常/开启，黄=需检查/未配置，红=异常），其余文字跟随终端前景色，兼顾深色与浅色背景：

| 首页入口 | 分类内的功能 |
| --- | --- |
| `[1]` 运行概览 | 服务状态、受保护域名、各 jail 封禁数、定时任务 |
| `[2]` 站点与证书 | 查看、添加、删除反代站点；设置 Cloudflare API Token |
| `[3]` 防火墙 | 端口与协议：开放/关闭 TCP、UDP 端口（可限制来源 IP/CIDR）、切换 IPv4/IPv6 入站；IP 访问控制：查看、封禁、解封 IP、管理白名单；规则维护：查看、重新应用规则 |
| `[4]` SSH 与登录 | 连接设置：修改 SSH 监听端口；认证方式：全局密码/密钥认证开关；root 凭据：公钥增删、修改 root 密码 |
| `[5]` 情报与上报 | 情报同步：立即同步；AbuseIPDB 上报：发送队列、设置 API Key、开关自动上报 |
| `[6]` 系统维护 | 运行诊断：近期日志；版本维护：更新；卸载 |

添加站点只需输入域名和上游（本地或公网 IP:端口），面板自动生成受保护的反代配置（`import abuseguard` 和按需 TLS）。白名单支持面板内增删，**新增会自动解封该 IP** 并重载 fail2ban。首页显示防火墙状态及情报最后同步时间。

更新会在校验前用 `caddy fmt` 规范化主 Caddyfile 和 `/etc/caddy/sites/*.caddy`，并删除 Caddy 明确判定为冗余的精确指令 `header_up X-Forwarded-Host {host}` 或 `header_up X-Forwarded-Host {http.request.host}`；其他反代配置和请求头均保留。

安装或更新会自动启用 AbuseGuard 防火墙并设置开机恢复，无需另行确认。首次建立配置时开放检测到的所有 SSH 端口、443/tcp 和 443/udp，其余入站端口默认丢弃；80/tcp 不默认开放，需要 HTTP 访问或跳转时可在面板手动放行。已有配置则保留用户开放和关闭的端口，并补齐当前 SSH 端口。保留已建立连接、回环、ICMP（含 IPv6 邻居发现）及 DHCP，出站流量不受限制。面板拒绝关闭当前 SSH 会话端口和唯一的 SSH 端口；关闭其他端口只阻止新连接。

「SSH 与登录」中的「修改 SSH 端口」会让新旧端口同时监听：校验 `sshd -t`，放行新端口，重载 sshd 并确认新旧端口都在监听，任一步失败恢复原配置；成功后同步 fail2ban 的 SSH 上报端口。请先用新端口重新登录确认，再到「防火墙」关闭旧端口：面板会删除对应的 `Port` 指令并关闭旧端口的防火墙放行；当前会话端口和唯一的 SSH 端口不允许关闭。没有 `Port` 指令时，在 `/etc/ssh/sshd_config.d/99-abuseguard-port.conf` 写入新旧两个端口；已有一个 `Port` 指令时保留原文件，新端口写入该 drop-in；出现多个 `Port` 指令时拒绝。新端口继承旧端口在防火墙中的来源限制；若新端口已有不兼容的来源规则，需先在「防火墙」中调整。切换前需先在云安全组或上游防火墙放行新端口。`ssh.socket` 激活方式下面板会拒绝修改。

「认证方式」通过 `/etc/ssh/sshd_config.d/00-abuseguard-auth.conf` 管理密码登录和密钥登录的开关：文件名以 `00-` 开头排序第一，sshd 首值生效，天然压过主配置全局指令和 `50-cloud-init.conf` 之类排序靠后的 drop-in。关闭任一方式需要输入 `yes` 确认；关闭密码认证前会验证 root 的无附加限制公钥、文件权限和当前连接的有效 SSH 配置；关闭密钥认证前会检查 root 密码状态及其能否独立认证，无法确认时拒绝。只有真正压不过面板的指令才拒绝修改：排序更靠前的 `00-` 外部 drop-in、主配置或 drop-in 的 Match 块内的指令、或主配置缺少 `Include`（此时 drop-in 不生效）；旧版本的 `99-abuseguard-auth.conf` 会自动迁移到新名字。`ssh.socket` 激活方式下同样拒绝。「添加公钥」写入 root 的 authorized_keys（按类型+blob 去重、自动修权限，支持 ssh-ed25519、ssh-rsa、ECDSA 和 sk- 硬件密钥）；删除最后一把有效公钥前会检查 root 密码条件并要求确认。「修改 root 密码」调用 `chpasswd`，两次输入一致才生效。面板管理全局认证开关，不修改 `PermitRootLogin`；全局密码认证开启后，root 可能仍受 SSH 策略限制。取不到 `SSH_CONNECTION`、启用 `UseDNS` 或缺少 `ssh-keygen` 时，面板无法确认备用登录方式并会拒绝危险操作。键盘交互认证可能独立允许密码。

开放端口时可填写来源 IPv4/IPv6 地址或 CIDR，留空表示所有来源；同一端口可以有多条来源规则，关闭端口时按编号选择要移除的那条。协议族有两个开关：IPv4 入站默认开启，IPv6 入站默认关闭；关闭某个协议族后，新的该协议族入站连接会被丢弃，已建立连接、回环、ICMP 和 DHCP 仍然保留。关闭当前 SSH 会话所在的协议族需要输入 `yes` 确认，会话断开后需要控制台恢复。重新应用规则和安装更新只会补齐缺失的 SSH 端口，不会把已有来源限制加宽为所有来源。SSH 改端口时，新端口继承旧端口的所有来源规则。

端口配置仅保存在 `/etc/caddy-abuseguard/firewall.nft`，由独立的 `inet caddy_abuseguard` 表执行。修改先通过 `nft -c` 校验，再以单次事务应用；一次性 systemd 服务负责开机恢复，无新增常驻进程。菜单可重新应用规则；卸载只移除本项目的表。IP 封禁继续复用 fail2ban，保留原有白名单、90 天封禁和不上报手动封禁的规则。

其他脚本可用 `ag --firewall-open tcp 12345` 或 `ag --firewall-open udp 12345` 非交互放行单个端口，沿用面板的校验和持久化流程，失败返回非零状态。本 fork 的 `sing-box-yg` 会在创建节点、改端口和配置内网落地入口时调用此接口；请先更新 AbuseGuard 至 v0.3.5 或以上，再使用新版 `sb`。此联动仅处理操作明确指定的端口，不自动扫描服务或关闭旧端口；云安全组仍需单独放行。

接管和修改端口前会检查现有 nftables 入站链：若发现其他有效入站规则或默认丢弃策略（Fail2Ban 除外），操作会报错并列出冲突链，需先迁移或停用对应规则后重试，避免面板放行却仍被旧规则拦截。云安全组及容器发布端口等转发流量仍由对应平台管理。白名单只豁免 IP 封禁，不绕过端口策略。其他工具若清空整个 nftables ruleset，需要在面板重新应用防火墙规则。新增 HTTPS 反代站点通常只需已有的 443，无需向公网开放反代上游端口。

## 防护模型

| Jail | 触发条件 | 阈值 | 封禁对象 |
| --- | --- | --- | --- |
| `caddy-intel` | 对受保护站点的任意请求 | 命中 1 次 | 仅威胁情报名单上的 IP |
| `caddy-rate-local` | 对受保护站点的任意请求 | 60 秒内 120 次 | 任意非白名单 IP（仅本地封禁） |
| `caddy-probe-h1` | 用 HTTP/1.1 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |
| `caddy-probe-h2` | 用 HTTP/2 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |
| `sshd`（安装时启用） | SSH 认证失败 | 沿用该 jail 的实际阈值 | 任意非白名单 IP + 加入上报队列 |
| `sshd-intel`（安装时启用） | 命中 SSH 认证失败过滤器 | 命中 1 次 | 仅威胁情报名单上的 IP |

六个 jail 的封禁时长均为 90 天，使用相同的全端口、全协议封禁动作；`sshd` 沿用系统原有的日志来源、后端和检测阈值，未自定义时采用 fail2ban 的默认值。白名单 IP（`/etc/caddy-abuseguard/whitelist`）永不被 AbuseGuard 封禁或上报；手动封禁也检查白名单，只接受单个 IPv4/IPv6 地址；白名单仍支持 CIDR 网段。各 jail 独立记录封禁，某个 jail 解封不会撤销其他 jail 仍有效的封禁；面板解封会遍历所有 jail。「敏感路径」= `/.env`、`/.git`、`/phpmyadmin`、`/vendor/phpunit`、`/cgi-bin`（及其子路径）。

首次生成的 Caddy 配置只启用 HTTP/1.1 和 HTTP/2，不监听 HTTP/3，UDP/443 可供其他服务使用。全入口封禁只针对被封禁的源 IP，不占用任何端口。

## 威胁情报

在名单同步之前，intel jail 不封禁任何人。引擎会拉取一份公开的、源自 AbuseIPDB 的封禁名单，并拒绝加载明显异常偏小（<9 万）或偏大（>12 万）的名单；任何失败都会保留上一次的名单。刷新每 6 小时执行一次（也可通过面板手动触发）。

## AbuseIPDB 上报（可选）

配置里上报默认开启，但只有设置 API key 后事件才会入队。敏感路径探测固定上报为类别 `21`（Web App Attack）；`sshd` jail 产生的认证爆破封禁固定上报为 `18,22`（Brute-Force + SSH）。普通请求速率、Web/SSH 情报名单命中和面板手动封禁只在本地处理，不对外举报。

公开原因只写标准化行为、实际次数、检测窗口，以及 Web 事件的 HTTP 协议；不会出现 AbuseGuard 名称，也不包含主机名、具体路径、查询参数、请求头、请求正文、UA、SSH 用户名或原始日志。上报按 IP 遵守 15 分钟窗口；同一 IP 的后续不同事件在窗口内会留在队列延后发送，而不是丢弃。每天最多 1000 条。冲刷时会先把当前队列原子轮转为独立批次，因此发送期间新入队的记录会留在新队列。白名单无法可靠读取或状态文件损坏时，冲刷会停止并返回失败；临时 API 故障保留记录重试。冲刷每 10 分钟执行一次。要关闭外部举报，用面板 → `[5]` 情报与上报 → `[4]` 开关自动上报；关闭上报不影响任何本地封禁。

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
/usr/local/bin/ag                             控制面板
/usr/local/libexec/caddy-abuseguard           Go 引擎
/etc/caddy/Caddyfile                          全局配置 + AbuseGuard 导入
/etc/caddy/abuseguard.caddy                   (abuseguard) 片段
/etc/caddy/sites/<域名>.caddy                 每个受保护站点一个文件
/etc/caddy-abuseguard/config.json             引擎配置
/etc/caddy-abuseguard/whitelist               永不封禁名单
/etc/caddy-abuseguard/abuseipdb-report.key    AbuseIPDB key（可选）
/etc/fail2ban/jail.d/zz-caddy-abuseguard-report.local  启用 SSH 防护、情报检测和上报
/var/lib/caddy-abuseguard/                     情报名单 + 上报队列/状态
/var/log/caddy/abuseguard-access.json         隐私精简的访问日志
```

## 更新 / 卸载

```bash
ag                               # 面板：[6] 系统维护 → [2] 更新 / [3] 卸载
sudo ./uninstall.sh              # 交互选择：保守 / 彻底
sudo ./uninstall.sh --conservative   # 保守：删 AbuseGuard，保留 Caddy 和你的反代
sudo ./uninstall.sh --purge          # 彻底：按安装清单删 AbuseGuard 装的一切
sudo ./uninstall.sh --dry-run        # 只打印将删除什么，不做任何改动
```

面板修改过的 SSH 端口不会随卸载回滚（配置保留在 `/etc/ssh/sshd_config.d/99-abuseguard-port.conf`），避免恢复默认端口导致失联；如需改回，重装后在「SSH 与登录」中设置即可。

卸载**对称于安装**：安装时会记录一份清单（哪些是 AbuseGuard 新建的、哪些你原本就有）。

- **保守卸载**：只删 AbuseGuard 组件，并从 Caddyfile 摘掉 AbuseGuard 的引入（`import abuseguard`、snippet、自检站点），**保留你原有的 Caddy、账户和反代配置**。
- **彻底卸载**：再按清单删 AbuseGuard 安装的 Caddy/账户/配置 —— 但**装之前你已有的一律不动**（原本就有 Caddy 就不会删 Caddy）。清单丢失时自动降级为最保守处理。
- `/etc/caddy/sites` 中由 AbuseGuard 管理的站点，卸载时可选「保留反代、只去防护」或「一起删」；以后重新安装时，保留的站点会自动恢复 `import abuseguard` 防护。原有 Caddyfile 在安装时已备份为 `Caddyfile.pre-abuseguard`。

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
