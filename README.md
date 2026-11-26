# AbuseGuard

[English](README.en.md) | **简体中文**

AbuseGuard 是一个面向 Debian/Ubuntu 上 [Caddy](https://caddyserver.com/) 或 Nginx 反向代理的即插即用滥用缓解层。它对直接到达源站的连接在防火墙层（nftables）封禁滥用及已知恶意 IP，并可选地将其自动上报到 [AbuseIPDB](https://www.abuseipdb.com/) —— 由 [fail2ban-rs](https://github.com/jasper-khan/fail2ban-rs)（纯 Rust 实现的 Fail2Ban 1.1.1 替代品）加一个小型 Rust 引擎驱动。

一条命令即可装好：加固版 Caddy（内置 `caddy-dns/cloudflare` TLS 模块）或发行版 Nginx（首次安装二选一，之后不可切换）、nftables 入站防火墙、fail2ban jail、威胁情报同步、可选上报器，以及交互式 `ag` 控制面板。

## 工作原理

```
访客 ─▶ Caddy / Nginx（受保护站点）
             │  写入隐私精简的 JSON 访问日志
             ▼
         fail2ban ──(速率/探测/SSH 行为)──▶ nftables 按源 IP DROP 全部端口/协议
             │
             └─(敏感路径探测)─▶ 引擎入队 ─▶ 上报队列 ──(定时器)──▶ AbuseIPDB

情报名单 ──(每 6 小时，引擎校验)──▶ 根权限应用 ──▶ 独立 nft 情报集合 ──▶ DROP 名单内源 IP
                                                   └─ 白名单例外只在情报链 return
```

- 反向代理（Caddy 或 Nginx）为每个到受保护站点的请求打标签，只记录 fail2ban 所需的字段（客户端 IP、协议、标签）——不记录路径、主机名、请求头或查询串。
- 安装时启用三个 Web 行为 jail 和 `sshd`，共用同一份白名单。任一 jail 封禁某个 IP 后，nftables 会拦截该源 IP 到本机所有端口、所有协议的流量，包括 SSH。
- 威胁情报不再经过 fail2ban：同步后由根权限应用把整份名单装进独立的内核集合，名单内的源 IP 在建立连接前即被丢弃；集合独立于端口防火墙表，修改端口不会重建它。
- 白名单只有一份：面板改动会同时更新 fail2ban 的 `ignoreip` 和 nft 情报例外。手工编辑文件后需要显式应用，见「威胁情报」。
- 一个 Rust 引擎（依赖集小且锁定、单个静态二进制）负责校验名单、冲刷上报队列并加载内核策略。只有根权限子命令 `policy-apply` 会写 nftables/fail2ban；同步、上报、入队等普通命令始终以非特权用户运行。

## 环境要求

- Debian 11/12 或 Ubuntu 20.04+（amd64 或 arm64），需 root（sudo）。
- 所有 nftables 封禁都按“到达本机的源 IP”执行，因此只对客户端直接连接源站的站点有效（包括 Cloudflare DNS-only）。经 CDN 或自建代理转发时，内核看到的源地址是代理的边缘 IP，不是访客 IP：威胁情报拦截无法作用于这类被代理的请求；行为 jail 依据反代记录的 `client_ip` 决定封谁，但同样无法阻止经代理到达的访客流量。本工具不解决未知 IP 或分布式 CC。

## 安装

安装器会检查四个 jail 的有效配置和启动状态。若旧的 `jail.local` 或 `jail.d/*.local` 禁用了其中某个 jail（例如 `[sshd] enabled = false`），安装会报错；请解除禁用冲突后重试。安装器不会自动改写这些自定义文件。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jasper-khan/abuseguard/main/install.sh)
```

或克隆后运行：

```bash
git clone https://github.com/jasper-khan/abuseguard
cd abuseguard
sudo ./install.sh                 # 从最新 release 下载预编译引擎
sudo ./install.sh --from-source   # 或在本地用 Rust 编译引擎（需要 cargo）
sudo ./install.sh --proxy=nginx   # 首次安装选择 Nginx（可与 --from-source 任意顺序组合）
```

默认安装和面板更新会先确定 GitHub 最新已发布 release，再使用该版本的源码、配置和引擎；从克隆目录运行默认安装也遵循此规则。引擎在临时文件中通过校验和、启动及目标版本检查后才替换旧文件。`--from-source` 和 `ABUSEGUARD_ENGINE_BIN` 仍使用本地源码及配置。

安装器是幂等的：已有的 config、whitelist、key 和无关的反代配置都会保留。Caddy 模式下，旧版或手工写在主 Caddyfile 中的 AbuseGuard 受保护站点，会迁移为标准的 `/etc/caddy/sites/<域名>.caddy`，站点内统一使用 `import abuseguard`；主配置、已有站点和防护片段先在候选副本上处理，完整配置通过校验后才替换正式文件，替换失败会回滚。Nginx 模式下不改动既有站点文件，安装/添加/删除站点都先对包含现有站点与候选文件的完整配置做 `nginx -t` 检查。

安装器会自动从 `jasper-khan/fail2ban-rs` 拉取最新 release 并校验 SHA-256 后安装 `fail2ban-rs` 到 `/usr/local`，同时补齐 `rsyslog`、`nftables`、`logrotate` 等运行依赖（不再通过 `apt` 安装发行版 Python `fail2ban`），新装且尚未配置时自动创建 `/etc/logrotate.d/fail2ban`。若机器上已有发行版 `fail2ban`，安装器会先用暂存的 `fail2ban-rs` 校验配置、仅停止实际活跃的旧单元并无缝接管原有 `/etc/fail2ban` 与 SQLite 数据库，待校验 `fail2ban.service` 主进程确为 `/usr/local/bin/fail2ban-server`、无指向 `/usr/bin/fail2ban-*` 的自定义 unit/drop-in 且全部 jail 就绪后，再自动 `apt-get remove fail2ban`（保留配置与数据库，不 purge）；更新时若已是最新 `fail2ban-rs` 则跳过下载，沿用原有 `idle` 暂停检测路径（最后重启 `fail2ban.service` 挂载配置并从数据库恢复封禁）。`rsyslog` 为依赖 `/var/log/auth.log` 的自定义配置保留兼容，AbuseGuard 的网站防护仍使用独立的隐私精简 JSON 日志。已有 Caddy 服务中的 Cloudflare token 会安全写入 `/etc/caddy/.env`，Nginx 模式则写入 `/etc/caddy-abuseguard/cloudflare.ini`；两者都不会在终端显示。

首次安装会**交互询问**两个可选密钥 —— Cloudflare API token（用 DNS-01 签发 TLS 证书）和 AbuseIPDB API key（用于自动上报）。**直接回车即可跳过**，AbuseIPDB key 输入时不会回显；两者都能之后随时在面板里设置。更新时会保留现有密钥、跳过这些询问，并在成功后自动重新加载面板。装完终端会醒目显示进面板的命令：

```bash
ag
```

> 在无终端的环境（CI / nohup / 管道）里，安装会自动跳过询问；也可显式设 `ABUSEGUARD_NONINTERACTIVE=1` 强制跳过。
>
> 设置 `ABUSEGUARD_REPO=you/abuseguard` 可从你自己的 fork 安装。

### 反向代理后端：Caddy 或 Nginx

首次安装必须选定一个反向代理后端；选择会写入 root 所有的 `/etc/caddy-abuseguard/web-server`（内容严格为 `caddy` 或 `nginx`，只读取、不 source），并在该安装的整个生命周期内固定：

- 交互安装会询问使用 Caddy（默认，直接回车）还是 Nginx。非交互安装默认 Caddy；要装 Nginx 请显式传 `--proxy=nginx`。
- `--proxy=caddy|nginx` 可与 `--from-source` 以任意顺序组合；未知参数或非法值直接报错退出。
- 更新不需要、也不读取该参数，始终沿用已记录的后端；若显式传入的 `--proxy` 与已记录值不同，安装会在安装软件包或改动主机之前报错。检测到既有安装缺少后端记录（0.6 之前的安装或状态异常）时，安装会中止并提示先升级到 0.6.2，不会静默安装另一个后端。
- 不提供在 Caddy 与 Nginx 之间切换或迁移的功能。要更换后端只能卸载后重装。
- 安装拒绝与另一种反向代理共存：目标机器上只要检测到另一后端的二进制/软件包/服务（即使未运行），安装会在改动主机前中止；请先手动移除该后端。

两种后端共用同一 Rust 引擎、fail2ban jail/filter/action 标识、nftables 白名单与情报、上报队列和 `ag` 面板；区别只在反向代理、TLS 签发与访问日志来源。

Caddy 后端保留原有行为：加固的 `/usr/local/bin/caddy`（内置 `caddy-dns/cloudflare`）、`/etc/caddy` 布局、DNS-01 与 `import abuseguard`。

Nginx 后端使用发行版 `nginx` 服务、`certbot` 与 `certbot-dns-cloudflare`，不替换或新增 Nginx systemd 单元。安装前会预检发行版 Nginx 是否编译了 `http_ssl_module`/`http_v2_module`，并确认 Cloudflare DNS 插件可导入；不满足时在改动站点前中止：

- 证书只用 DNS-01（`certbot certonly --dns-cloudflare`），每个域一个 `--cert-name abuseguard-<域名>`；不使用 `--nginx`/`--standalone`/webroot/HTTP-01，也不监听或开放 80/tcp。续期沿用系统 certbot 定时器，并保存认证器、凭据与部署钩子；证书部署成功后由 `/usr/local/libexec/abuseguard-nginx-deploy` 执行 `nginx -t`、reload，并确认新 worker 真正接管（重载未生效会报告失败，不会假装成功）。
- Cloudflare API token 保存在 root:root 0600 的 `/etc/caddy-abuseguard/cloudflare.ini`，不会打印、不会 source，也不随保存动作重启 Nginx。安装时可跳过 token，但之后添加站点会明确失败，直到在面板中设置；没有 acme.sh 或 HTTP-01 回退。
- 受保护站点为 `/etc/nginx/sites-available/abuseguard-<域名>.conf`，软链到 `sites-enabled`；HTTP 级共享配置在 `/etc/nginx/conf.d/abuseguard.conf`。部署钩子与共享片段由项目所有，其他 Nginx 配置不受影响。
- 访问日志为 `/var/log/nginx/abuseguard-access.json`：最小 JSON，只保留 `ts`、`client_ip`、`proto` 和 AbuseGuard 标签，不记录 URI、查询串、Host、请求头或正文；受保护站点不再额外写默认 combined 访问日志。
- 只信任来自官方 Cloudflare IPv4/IPv6 网段的 `CF-Connecting-IP`；其他来源伪造的同名头会被忽略，日志使用归一化后的可信客户端地址。Cloudflare 网段拉取失败时使用内置快照，绝不信任所有来源。反代保留原始 `Host`（含端口），`X-Real-IP`/`X-Forwarded-For` 重写为可信客户端地址，不转发客户端伪造的 XFF；不是受管域名的 Host/SNI 直接返回 404，不会落到其他站点上游。
- 公网只监听 443/tcp（HTTP/1.1 与 HTTP/2），不启用 HTTP/3/QUIC。由安装器新装 Nginx 时会抑制软件包自启并只删除本次新建的发行版默认站点；已有的 Nginx 站点保持不动。AbuseGuard 自己不生成 `listen 80`，自检站点只绑定回环地址。
- 证书在 Cloudflare 灰云（DNS-only）和橙云（代理）下都可用；橙云时 Cloudflare 的 SSL/TLS 模式需为 Full (strict)。经 CDN 代理的源站 IP 限制问题见「环境要求」。

### 网络与下载

所有 GitHub 下载（仓库 tarball、预编译引擎与 Caddy、校验文件、`ag` 面板的更新/卸载脚本）都**只走 GitHub 直连**，项目不内置任何第三方镜像或代理链。更新与卸载会先解析最新已发布 release 的 tag，再从该 tag 拉取脚本与产物——脚本和它安装的一切始终来自同一个已发布版本。若你的网络无法直连 GitHub，请在运行前设置标准的 `https_proxy`/`HTTPS_PROXY` 环境变量（curl 原生支持；此时该代理即你自己选择的信任锚），或在可直连的机器上克隆仓库后用 `--from-source` 安装。

引擎和带 cloudflare 模块的 Caddy 都从本仓库的 GitHub release 下载（Caddy 由 CI 用 `xcaddy` 构建）。若系统已存在带 `caddy-dns/cloudflare` 模块的 Caddy，Caddy 模式安装器会自动检测并保留、跳过下载。Nginx 模式只从 release 下载 Rust 引擎，Nginx/Certbot 使用发行版软件包。

**完整性校验（强制）**：下载的 engine 与 Caddy **必须**通过 release 里 `SHA256SUMS.txt` 的校验。校验文件体积极小，会带重试直连获取。**校验不符、或校验文件就是拿不到，都会中止安装**（不会“跳过校验继续装”）；如遇网络问题，请重试或用 `--from-source` 本地编译。

**Cloudflare IP 段兜底**：生成 Caddyfile 的 `trusted_proxies` 或 Nginx 的信任来源配置时会拉取 Cloudflare 的官方 IPv4/IPv6 网段；若网络受限拉取失败，会退回内置快照（`assets/caddy/cloudflare-ips.fallback`），避免信任范围只剩回环或过窄——那会让所有访客都被当成 Cloudflare 边缘 IP（或反之信任伪造头），导致误封或整站不可用。

**已有 Caddy 迁移（仅 Caddy 模式）**：若安装前已有 Caddyfile，安装器会先备份原文件，再把其中可明确识别的“单一公网域名 + `reverse_proxy`”站点完整迁入 `/etc/caddy/sites/<域名>.caddy`，并加入 `import abuseguard`。站点原有的 TLS、路由、请求头和上游配置均保留；全局块、snippet、IP/端口监听及非反代站点仍留在主 Caddyfile。迁移后的完整配置必须通过 Caddy 校验才会生效。Nginx 模式不迁移或改写其他站点，只管理项目自己的 `conf.d/abuseguard.conf`、`abuseguard-<域名>.conf` 和部署钩子。

## 控制面板

直接运行 `ag`（面板需要 root；以普通用户运行会自动通过 sudo 提权，必要时提示输入密码）。标题会显示当前 AbuseGuard 引擎版本，首页会显示当前 SSH 端口和受保护站点数；“封禁记录”每 30 分钟重新查询各 jail，无需进入菜单手动刷新：

面板使用 `=` 分隔线、左对齐的 `标签 : 值` 状态区和单列编号菜单；首页显示防护结论、封禁记录、情报集合大小与行为封禁数、上报状态、SSH 端口、站点数与版本，子页面沿用同一结构。状态值用颜色区分（绿=正常/开启，黄=需检查/未配置，红=异常），其余文字跟随终端前景色，兼顾深色与浅色背景：

| 首页入口 | 分类内的功能 |
| --- | --- |
| `[1]` 运行概览 | 服务状态、受保护域名、各 jail 封禁数、定时任务 |
| `[2]` 站点与证书 | 查看、添加、删除反代站点；设置 Cloudflare API Token |
| `[3]` 防火墙 | 端口与协议：开放/关闭 TCP、UDP 端口（可限制来源 IP/CIDR）、切换 IPv4/IPv6 入站；IP 访问控制：查看、封禁、解封 IP、管理白名单；规则维护：查看、重新应用规则 |
| `[4]` SSH 与登录 | 连接设置：修改 SSH 监听端口；认证方式：全局密码/密钥认证开关；root 凭据：公钥增删、修改 root 密码 |
| `[5]` 情报与上报 | 情报同步：立即同步（校验后应用内核策略）；AbuseIPDB 上报：发送队列、设置 API Key、开关自动上报 |
| `[6]` 系统维护 | 运行诊断：近期日志；版本维护：更新；卸载 |

添加站点只需输入域名和上游（本地或公网 IP:端口），面板按当前后端生成受保护反代配置：Caddy 写 `import abuseguard` 与按需 DNS-01 TLS；Nginx 写 `abuseguard-<域名>.conf`（反代、仅 443/h1/h2、DNS-01 证书名 `abuseguard-<域名>`）。Nginx 模式在写入受管文件后，对包含现有站点与候选文件的完整加载配置执行 `nginx -T` 校验，通过后才 reload；校验或 reload 失败会移除新站点并恢复原有启用状态（证书材料保留），不会留下半启用站点。未设置 Cloudflare token 时，添加站点会明确失败而不会退回 HTTP-01。白名单支持面板内增删：改动会同时应用到 fail2ban 的 `ignoreip` 与 nft 情报例外，**新增条目会解封它覆盖的行为封禁（含 CIDR 内的地址）**；若该 IP 仍在情报名单中，需要白名单条目才能放行。首页分别显示防火墙状态、情报名单条目数与行为封禁数，不会把整份情报集合打印到终端。

更新会在校验前用 `caddy fmt` 规范化主 Caddyfile 和 `/etc/caddy/sites/*.caddy`（仅 Caddy 模式），并删除 Caddy 明确判定为冗余的精确指令 `header_up X-Forwarded-Host {host}` 或 `header_up X-Forwarded-Host {http.request.host}`；其他反代配置和请求头均保留。

安装或更新会自动启用 AbuseGuard 防火墙与原生白名单/情报策略，并设置开机恢复，无需另行确认。更新时会把各 jail 设为 idle：检测暂停，但已有封禁继续在内核生效；装好新引擎与 jail 后再重启 fail2ban。仅在 idle 不可用时才回退为停止 fail2ban（此时行为封禁会短暂失效，重启后由数据库恢复）。替换引擎前失败会恢复原 jail 配置并继续检测；替换后的任何失败也会恢复旧引擎与旧 jail 配置、重启旧检测并明确告警，不会把检测留在暂停状态；已有内核封禁继续生效。fail2ban 的原生 `ignoreip` 按 jail 分别保留，sshd 的豁免不会扩散到 Web jail；修改或删除原生豁免后，下次应用即生效。首次建立配置时开放检测到的所有 SSH 端口、443/tcp 和 443/udp，其余入站端口默认丢弃；80/tcp 不默认开放，需要 HTTP 访问或跳转时可在面板手动放行。已有配置则保留用户开放和关闭的端口，并补齐当前 SSH 端口。保留已建立连接、回环、ICMP（含 IPv6 邻居发现）及 DHCP，出站流量不受限制。面板拒绝关闭当前 SSH 会话端口和唯一的 SSH 端口；关闭其他端口只阻止新连接。

「SSH 与登录」中的「修改 SSH 端口」会让新旧端口同时监听：校验 `sshd -t`，放行新端口，重载 sshd 并确认新旧端口都在监听，任一步失败恢复原配置；成功后同步 fail2ban 的 SSH 上报端口。请先用新端口重新登录确认，再到「防火墙」关闭旧端口：面板会删除对应的 `Port` 指令并关闭旧端口的防火墙放行；当前会话端口和唯一的 SSH 端口不允许关闭。没有 `Port` 指令时，在 `/etc/ssh/sshd_config.d/99-abuseguard-port.conf` 写入新旧两个端口；已有一个 `Port` 指令时保留原文件，新端口写入该 drop-in；出现多个 `Port` 指令时拒绝。新端口继承旧端口在防火墙中的来源限制；若新端口已有不兼容的来源规则，需先在「防火墙」中调整。切换前需先在云安全组或上游防火墙放行新端口。`ssh.socket` 激活方式下面板会拒绝修改。

「认证方式」通过 `/etc/ssh/sshd_config.d/00-abuseguard-auth.conf` 管理密码登录和密钥登录的开关：文件名以 `00-` 开头排序第一，sshd 首值生效，天然压过主配置全局指令和 `50-cloud-init.conf` 之类排序靠后的 drop-in。关闭任一方式需要输入 `yes` 确认；关闭密码认证前会验证 root 的无附加限制公钥、文件权限和当前连接的有效 SSH 配置；关闭密钥认证前会检查 root 密码状态及其能否独立认证，无法确认时拒绝。只有真正压不过面板的指令才拒绝修改：排序更靠前的 `00-` 外部 drop-in、主配置或 drop-in 的 Match 块内的指令、或主配置缺少 `Include`（此时 drop-in 不生效）。`ssh.socket` 激活方式下同样拒绝。「添加公钥」写入 root 的 authorized_keys（按类型+blob 去重、自动修权限，支持 ssh-ed25519、ssh-rsa、ECDSA 和 sk- 硬件密钥）；删除最后一把有效公钥前会检查 root 密码条件并要求确认。「修改 root 密码」调用 `chpasswd`，两次输入一致才生效。面板管理全局认证开关，不修改 `PermitRootLogin`；全局密码认证开启后，root 可能仍受 SSH 策略限制。取不到 `SSH_CONNECTION`、启用 `UseDNS` 或缺少 `ssh-keygen` 时，面板无法确认备用登录方式并会拒绝危险操作。键盘交互认证可能独立允许密码。

开放端口时可填写来源 IPv4/IPv6 地址或 CIDR，留空表示所有来源；同一端口可以有多条来源规则，关闭端口时按编号选择要移除的那条。协议族有两个开关：IPv4 入站默认开启，IPv6 入站默认关闭；关闭某个协议族后，新的该协议族入站连接会被丢弃，已建立连接、回环、ICMP 和 DHCP 仍然保留。关闭当前 SSH 会话所在的协议族需要输入 `yes` 确认，会话断开后需要控制台恢复。重新应用规则和安装更新只会补齐缺失的 SSH 端口，不会把已有来源限制加宽为所有来源。SSH 改端口时，新端口继承旧端口的所有来源规则。

端口配置仅保存在 `/etc/caddy-abuseguard/firewall.nft`，由独立的 `inet caddy_abuseguard` 表执行。修改先通过 `nft -c` 校验，再以单次事务应用；`caddy-abuseguard-firewall.service` 负责开机恢复端口表，独立的 `caddy-abuseguard-policy.service` 负责开机恢复情报集合，两者都是一次性服务，无新增常驻进程。菜单可重新应用规则；卸载只移除本项目创建的表（端口表与独立的 `inet caddy_abuseguard_intel` 情报表）。行为封禁继续复用 fail2ban：保留白名单、90 天封禁和不上报手动封禁的规则；白名单同时驱动 fail2ban `ignoreip` 与情报例外，不再使用按请求执行的 `ignorecommand`。

其他脚本可用 `ag --firewall-open tcp 12345` 或 `ag --firewall-open udp 12345` 非交互放行单个端口，沿用面板的校验和持久化流程，失败返回非零状态。外部修改白名单或情报名单后，需要运行 `sudo ag --policy-apply` 立即校验并应用；`ag --firewall-apply` 只重建端口表，不触碰情报表。本 fork 的 `sing-box-yg` 会在创建节点、改端口和配置内网落地入口时调用此接口；请先更新 AbuseGuard 至 v0.3.5 或以上，再使用新版 `sb`。此联动仅处理操作明确指定的端口，不自动扫描服务或关闭旧端口；云安全组仍需单独放行。

接管和修改端口前会检查现有 nftables 入站链：若发现其他有效入站规则或默认丢弃策略（本项目的受管表与 Fail2Ban 的表除外），操作会报错并列出冲突链，需先迁移或停用对应规则后重试，避免面板放行却仍被旧规则拦截。云安全组及容器发布端口等转发流量仍由对应平台管理。白名单只豁免 IP 封禁，不绕过端口策略。其他工具若清空整个 nftables ruleset，需要在面板重新应用防火墙规则。新增 HTTPS 反代站点通常只需已有的 443，无需向公网开放反代上游端口。

## 防护模型

| Jail | 触发条件 | 阈值 | 封禁对象 |
| --- | --- | --- | --- |
| `caddy-rate-local` | 对受保护站点的任意请求 | 60 秒内 120 次 | 任意非白名单 IP（仅本地封禁；面板手动封禁也写入此 jail） |
| `caddy-probe-h1` | 用 HTTP/1.1 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |
| `caddy-probe-h2` | 用 HTTP/2 扫描敏感路径 | 10 分钟内 5 次 | 任意非白名单 IP + 加入上报队列 |
| `sshd`（安装时启用） | SSH 认证失败 | 沿用该 jail 的实际阈值 | 任意非白名单 IP + 加入上报队列 |

三个 Web jail 与 `sshd` 的封禁时长均为 90 天，使用相同的全端口、全协议封禁动作；`sshd` 沿用系统原有的日志来源、后端和检测阈值，未自定义时采用 fail2ban 的默认值。白名单 IP（`/etc/caddy-abuseguard/whitelist`）永不被 AbuseGuard 封禁或上报；手动封禁也检查白名单，只接受单个 IPv4/IPv6 地址；白名单仍支持 CIDR 网段。各 jail 独立记录封禁，某个 jail 解封不会撤销其他 jail 仍有效的封禁；面板解封会遍历所有 jail。情报拦截不经过 jail，命中名单的源 IP 由独立的内核集合直接丢弃（见「威胁情报」）。「敏感路径」= `/.env`、`/.git`、`/phpmyadmin`、`/vendor/phpunit`、`/cgi-bin`（及其子路径）。

首次生成的 Caddy 配置只启用 HTTP/1.1 和 HTTP/2；Nginx 站点只监听 443 并启用 HTTP/1.1 与 HTTP/2。两者都不监听 HTTP/3，UDP/443 可供其他服务使用。全入口封禁只针对被封禁的源 IP，不占用任何端口。

## 威胁情报

威胁情报以内核集合的形式生效，不再是“命中一次就封 90 天”的 jail。每 6 小时（也可通过面板手动触发）引擎拉取一份公开的、源自 AbuseIPDB 的名单：只保留 IPv4，拒绝明显异常偏小（<9 万）或偏大（>25 万）的结果，校验通过后原子写入 `intel.txt`；任何下载或解析失败都保留上一份名单。

随后的根权限应用（`caddy-abuseguard policy-apply`，由 `caddy-abuseguard-policy.service` 在开机时、以及 `caddy-abuseguard-sync.service` 在每次同步后运行）会在进程内逐行严格校验白名单和情报名单，再以单次 nft 事务重建集合，成功后写入根所有的开机快照。从未建立过策略时允许空集合；已有名单缺失、损坏、超界或应用/保存失败时，保留上一次生效的内核策略和快照，不会用空集合或半份名单覆盖。

名单跟随：新列入的源 IP 在下一次同步后即被拦截，移出名单后不再被拦截，不再有固定 90 天的情报封禁。白名单例外只在情报链内 `return`，不会全局接受流量，所以白名单 IP 仍受端口防火墙约束；重叠的 CIDR 例外同样有效。修改端口只重建端口表，情报集合独立存在。

手工编辑 `/etc/caddy-abuseguard/whitelist` 后需要显式应用：`sudo ag --policy-apply`（否则要等到下一个 6 小时同步周期）；面板内增删会立即应用，安装与更新也会重新应用。应用失败时保留上一次生效的策略，不会出现 fail2ban 已放开而内核仍拦截（或相反）的静默分裂状态。

解封与情报的关系：面板“解封 IP”只清除各 jail 的定时行为封禁。如果该 IP 仍在情报名单上，内核拦截会继续生效——要放行一个仍被名单命中的源，请把它加入白名单。

代理/CDN 的限制见「环境要求」：内核只能按到达本机的源地址匹配，无法对经代理转发的访客做名单拦截。

## AbuseIPDB 上报（可选）

配置里上报默认开启，但只有设置 API key 后事件才会入队。敏感路径探测固定上报为类别 `21`（Web App Attack）；`sshd` jail 产生的认证爆破封禁固定上报为 `18,22`（Brute-Force + SSH）。普通请求速率、情报拦截和面板手动封禁只在本地处理，不对外举报。

公开原因只写标准化行为、实际次数、检测窗口，以及 Web 事件的 HTTP 协议；不会出现 AbuseGuard 名称，也不包含主机名、具体路径、查询参数、请求头、请求正文、UA、SSH 用户名或原始日志。上报按 IP 遵守 15 分钟窗口；同一 IP 的后续不同事件在窗口内会留在队列延后发送，而不是丢弃。每天最多 1000 条。冲刷时会先把当前队列原子轮转为独立批次，因此发送期间新入队的记录会留在新队列。白名单无法可靠读取或状态文件损坏时，冲刷会停止并返回失败；临时 API 故障保留记录重试。冲刷每 10 分钟执行一次。要关闭外部举报，用面板 → `[5]` 情报与上报 → `[4]` 开关自动上报；关闭上报不影响任何本地封禁。

## 接入你的站点

### Caddy 模式

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

### Nginx 模式

推荐用面板「站点与证书」添加：它会为域名签发 `abuseguard-<域名>` 证书，写 `/etc/nginx/sites-available/abuseguard-<域名>.conf` 并软链到 `sites-enabled`；随后对包含现有站点与候选文件的完整加载配置执行 `nginx -T` 校验，通过后才 reload，并确认新 worker 真正接管（监听地址/端口被占用时不会再误报成功），失败会移除新站点并恢复原有启用状态（证书材料保留），不会留下半启用站点。受保护站点关闭了响应缓冲并设置了 1 小时上游读取超时：SSE/流式响应首块不会被缓冲，空闲 WebSocket 也不会像 Nginx 默认那样在 60 秒被切断。受保护站点文件由项目生成，包含共享的日志/标签指令；如需手工调整，改完执行 `sudo nginx -t && sudo systemctl reload nginx`。

续期由系统 certbot 定时器负责：`/etc/letsencrypt/renewal/abuseguard-<域名>.conf` 保存 DNS-01 认证器与凭据引用，`/etc/caddy-abuseguard/cloudflare.ini` 保存 root-only token，`/usr/local/libexec/abuseguard-nginx-deploy` 是部署钩子。只有证书成功部署后才执行 `nginx -t`、reload 并确认新 worker 接管；重载未生效会报告失败，续期失败不会中断现有 HTTPS。

两种模式都只反代 `域名 + IP:端口`，不接受 scheme、HTTPS 上游或通配符域名。

## 文件位置

两种后端共用：

```
/usr/local/bin/ag                             控制面板
/usr/local/libexec/caddy-abuseguard           Rust 引擎（policy-apply 为根权限子命令）
/etc/caddy-abuseguard/web-server              已选后端（严格为 caddy 或 nginx，root 所有）
/etc/caddy-abuseguard/config.json             引擎配置
/etc/caddy-abuseguard/whitelist               永不封禁名单
/etc/caddy-abuseguard/firewall.nft            端口防火墙配置 + 开机恢复
/etc/caddy-abuseguard/intel.nft               情报集合快照（根所有，开机恢复）
/etc/caddy-abuseguard/intel-allow.nft         白名单例外快照（根所有）
/etc/caddy-abuseguard/intel-applied.json      最近一次应用时间与条目数
/etc/caddy-abuseguard/abuseipdb-report.key    AbuseIPDB key（可选）
/etc/fail2ban/jail.d/zz-caddy-abuseguard-report.local  启用 SSH 防护和上报
/etc/fail2ban/jail.d/zzz-caddy-abuseguard-policy.local 由白名单生成的原生 ignoreip
/var/lib/caddy-abuseguard/                     情报名单 + 上报队列/状态
```

Caddy 模式：

```
/usr/local/bin/caddy                          Caddy（内置 caddy-dns/cloudflare）
/etc/caddy/Caddyfile                          全局配置 + AbuseGuard 导入
/etc/caddy/abuseguard.caddy                   (abuseguard) 片段
/etc/caddy/sites/<域名>.caddy                 每个受保护站点一个文件
/etc/caddy/.env                               CF_API_TOKEN（0640）
/var/log/caddy/abuseguard-access.json         隐私精简的访问日志
```

Nginx 模式：

```
/etc/nginx/conf.d/abuseguard.conf             HTTP 级共享配置（日志、标签、信任来源）
/etc/nginx/conf.d/zz-abuseguard-selftest.conf 仅回环的自检站点
/etc/nginx/snippets/abuseguard-cloudflare.conf 仅官方 CF 网段的 real_ip 信任配置
/etc/nginx/sites-available/abuseguard-<域名>.conf   每个受保护站点一个文件
/etc/nginx/sites-enabled/abuseguard-<域名>.conf     指向 sites-available 的软链
/usr/local/libexec/abuseguard-nginx.sh        根所有的 Nginx 运行时助手（只 source）
/usr/local/libexec/abuseguard-nginx-deploy    证书部署钩子（nginx -t 后 reload）
/etc/logrotate.d/abuseguard-nginx             访问日志轮转与重开
/etc/caddy-abuseguard/package-ownership       安装前的 Nginx/Certbot 软件包归属（root 所有）
/etc/caddy-abuseguard/cloudflare.ini          DNS-01 凭据（root:root 0600）
/etc/letsencrypt/live/abuseguard-<域名>/      证书（每域一个 lineage）
/etc/letsencrypt/renewal/abuseguard-<域名>.conf  certbot 续期配置
/var/log/nginx/abuseguard-access.json         隐私精简的访问日志
```

## 更新 / 卸载

```bash
ag                               # 面板：[6] 系统维护 → [2] 更新 / [3] 卸载
sudo ./uninstall.sh              # 交互选择：保守 / 彻底
sudo ./uninstall.sh --conservative   # 保守：删 AbuseGuard，保留反代和你的站点
sudo ./uninstall.sh --purge          # 彻底：按安装清单删 AbuseGuard 装的一切
sudo ./uninstall.sh --dry-run        # 只打印将删除什么，不做任何改动
```

面板修改过的 SSH 端口不会随卸载回滚（配置保留在 `/etc/ssh/sshd_config.d/99-abuseguard-port.conf`），避免恢复默认端口导致失联；如需改回，重装后在「SSH 与登录」中设置即可。

卸载**对称于安装**：安装时会记录一份清单（哪些是 AbuseGuard 新建的、哪些你原本就有）。后端选择同样不可变，卸载不会把安装切换到另一个后端。

- **保守卸载**：只删 AbuseGuard 组件。Caddy 模式从 Caddyfile 摘掉 `import abuseguard`、snippet 和自检站点；Nginx 模式在保留站点时（默认）保留受管站点、`conf.d/abuseguard.conf`、证书、`cloudflare.ini`、续期配置与部署钩子，只移除自检和核心组件；选择删除站点时才移除受管站点、项目 HTTP 配置/信任片段/logrotate、对应证书 lineage 和凭据，不碰其他 Nginx 配置。两种模式都**保留反向代理本身、账户和你的反代配置**。
- Nginx 模式下，保守卸载会保留证书、`/etc/caddy-abuseguard/cloudflare.ini`、续期所需的 Nginx 片段、certbot 续期配置与部署钩子，因此移除核心后 HTTPS 与自动续期继续工作。
- **彻底卸载**：再按清单删 AbuseGuard 安装的 Caddy/Nginx 包、账户和配置 —— 但**装之前你已有的一律不动**（原本就有 Caddy 或 Nginx 就不会删对应包）。Nginx 模式只删除项目创建且不再被引用的站点、证书 lineage、凭据和配置；若选择保留站点，Nginx/Certbot 软件包、证书、凭据与续期配置都会保留。绝不执行 `rm -rf /etc/nginx`、`rm -rf /etc/letsencrypt`、全局 `apt autoremove` 或关闭其他服务的 certbot 定时器。清单丢失时自动降级为最保守处理。
- 新装时会在 root 管理的 `/etc/caddy-abuseguard/install-manifest` 保存首次安装的归属记录，重试或升级不会覆盖。旧版本在 `/var/lib/caddy-abuseguard` 留下的清单不会自动成为彻底卸载的依据；缺少可信清单时，即使指定 `--purge` 也只做保守卸载并保留站点。无法验证后端模式或引擎不支持检查时，只清理核心组件，不改代理配置。
- 受管站点卸载时可选「保留反代、只去防护」或「一起删」；保留下来的 Nginx 站点若仍需续期文件，即使彻底卸载也会保留这些文件。以后重新安装时，保留且可识别的站点会恢复防护，不会被静默换成另一个后端。

卸载同时删除本项目的端口表、独立情报表、根所有开机快照和生成的白名单 jail 配置，保留 `fail2ban-rs` 本身，也不会改动其他 nftables 表或其他 fail2ban jail。

## 安全须知

- 反向代理本身不提供任何鉴权。凡是你对外暴露的站点，除非你自己加了鉴权，否则都是公开的。
- 安装器的自检站点只绑定回环地址（Caddy 为 `127.0.0.1:8080`；Nginx 同样不生成公网 80 端口站点），不会暴露公网 HTTP。
- 密钥（`*.key`、`.env`）权限为 0640；Nginx 的 `/etc/caddy-abuseguard/cloudflare.ini` 为 root:root 0600。两者都已被 git 忽略，切勿提交。
- Caddy 模式下载的二进制会用 `SHA256SUMS.txt` 校验（见「网络与下载」的完整性校验说明）；Nginx 模式使用发行版 `nginx`/`certbot` 包，安装清单只记录哪些包由本项目首次安装，避免卸载时误删系统原有软件。
- 威胁情报只以根所有的快照和内核集合生效：根权限子命令在进程内逐行校验白名单和已存储名单，绝不把下载到的原始文本当作 nft 规则执行；`/var/lib/caddy-abuseguard` 对 `abuseguard` 用户可写，因此不作为可执行策略来源。
- Caddy 以加固的 systemd 单元运行（`NoNewPrivileges`、`ProtectSystem=strict`、能力集限定、系统调用过滤等）；两个引擎定时任务和根权限策略应用单元同样加固。Nginx 使用发行版自带的 `nginx.service`（不替换单元）。
- Nginx 只信任官方 Cloudflare IPv4/IPv6 网段发来的 `CF-Connecting-IP`；来自其他来源的同名头会被忽略。受保护站点日志不含 URI、Host、请求头、正文或查询串，也不额外写默认 combined 访问日志。
- `/etc/caddy-abuseguard/web-server` 为 root 所有、只读取不执行；写入前严格校验 `caddy`/`nginx` 枚举，损坏或含糊的记录不会被当作安装另一个后端的许可。

## 构建 / 发布

- `engine-rs/` 是单个 Cargo crate，依赖集小且锁定；`engine-rs/Cargo.toml` 的 `version` 与顶层 `VERSION` 文件保持同步。
- CI 在 Ubuntu 上运行锁定的 Rust 引擎测试、shell/面板测试、真实 Caddy 日志契约、真实 Nginx → JSON → fail2ban-regex 契约（HTTP/1.1 与 HTTP/2、可信与伪造的 Cloudflare 头、隐私字段与日志轮转）以及隔离的 Nginx 配置回滚/证书部署集成测试；真实 nftables 和 systemd 沙箱门禁保持独立。
- 打 `vX.Y.Z` 标签会触发 [`.github/workflows/release.yml`](.github/workflows/release.yml)，它构建 `caddy-abuseguard-linux-{amd64,arm64}` 并附加到 release。`install.sh` 默认下载这些产物；Nginx 模式不发布也不下载这些资产，改用发行版软件包。
- 版本化的引擎产物发布后保持不变；每周/手动刷新只更新跟随上游的 Caddy，并重新生成覆盖全部现有产物的校验和与构建元数据。

架构与「失败即安全」规则详见 [docs/design.md](docs/design.md)。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
