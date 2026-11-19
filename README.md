# fanout（3m-ui / Mihomo 版）

基于 [byJoey/fanout](https://github.com/byJoey/fanout) 复刻，节点后端**仅支持 [kazeyukiro/3m-ui](https://github.com/kazeyukiro/3m-ui)**。

fanout 把 VPN Gate 公共节点变成相互隔离的 SOCKS5 出口，再通过 3m-ui 的 Mihomo 服务端路由，把不同 Listener 的入口流量分发到对应出口。Listener、代理用户、分享链接、服务端出站与路由全部通过 3m-ui REST API 管理，**不直接修改 3m-ui 的数据库或 YAML 文件**。

## 工作原理

```text
客户端
  └─ 3m-ui Listener :10001
       └─ Mihomo 规则 IN-PORT,10001,fanout-jp-home
            └─ Mihomo SOCKS5 出站 127.0.0.1:23000
                 └─ fanout SOCKS5
                      └─ network namespace foN
                           └─ OpenVPN → VPN Gate 节点
```

每条 VPN 隧道运行在独立 network namespace 中，因此 VPN 路由不会劫持母机网络。fanout 的 SOCKS5 监听在母机，只有代理连接进入对应 netns。

**3m-ui 必须与 fanout 运行在同一台 Linux 主机上。** Mihomo 出站固定连接 `127.0.0.1:<fanout端口>`，远程面板会连接它自己的回环地址，无法访问 fanout 隧道。

## 功能

- 按地区批量创建 VPN Gate 出口，支持每个国家批量创建。
- 每条出口独立随机 SOCKS5 端口与认证凭据，支持 UDP ASSOCIATE。
- 使用 3m-ui QuickCreate 创建 VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC v4/v5 Listener。
- 以现有 Listener 为模板批量复制，保留并合并代理用户绑定。
- 通过 `IN-PORT,<Listener端口>,fanout-<节点名>` 规则绑定出口。
- 换节点、改端口、重连和服务重启后自动同步绑定与 SOCKS5 出站。
- 导出普通链接、base64/明文订阅和 Mihomo YAML 订阅。
- 只清理由 fanout 管理且已不被引用的资源，保留用户在 3m-ui 中的其他配置。

## 环境与安装

需要：

- Linux、root 权限、可用的 `/dev/net/tun`。
- 同机运行且启用 REST API 的 3m-ui。
- systemd 或 OpenRC。
- Go 1.24+（仅从源码编译时需要）。

安装器会自动安装 OpenVPN、curl、tar、iproute 和 iptables，不再下载或运行 Xray。

### 从源码安装

```bash
git clone <你的复刻仓库地址>
cd fanout
sudo bash install.sh
```

### 使用预编译包

发布到自己的 GitHub 仓库后，将 `<owner>/<repo>` 换成实际仓库：

```bash
export REPO=<owner>/<repo>
bash <(curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/install.sh")
```

Alpine 先安装 bash：

```bash
apk add bash curl
```

## 配置 3m-ui

创建 `/var/lib/fanout/panel.yaml`：

```yaml
url: "http://127.0.0.1:8080" # 改成 3m-ui 实际地址，不需要手写 /api/v1
username: "admin"
password: "请换成实际密码"
# totp_code: "123456"          # 面板启用动态验证码时才需要
# insecure_skip_verify: true   # 仅自签 HTTPS 证书且明确接受风险时开启
```

然后限制权限并重启：

```bash
sudo chmod 600 /var/lib/fanout/panel.yaml
sudo systemctl restart fanout   # OpenRC 使用 sudo rc-service fanout restart
```

也可以用环境变量覆盖 YAML 中的对应项：

| 环境变量 | 说明 |
| --- | --- |
| `FANOUT_3M_UI_URL` | 3m-ui 地址 |
| `FANOUT_3M_UI_USERNAME` | 登录用户名 |
| `FANOUT_3M_UI_PASSWORD` | 登录密码 |
| `FANOUT_3M_UI_TOTP_CODE` | 动态验证码 |
| `FANOUT_3M_UI_INSECURE_SKIP_VERIFY` | 是否跳过 HTTPS 证书校验 |

注意：`totp_code` 是当前验证码而不是 TOTP 密钥。令牌过期后如果 3m-ui 要求重新验证，需要更新验证码；自动化部署建议使用专门的受限面板账号，并妥善保护凭据。

安装后访问安装器打印的随机路径与口令，也可以查看：

```bash
sudo cat /var/lib/fanout/basepath
sudo cat /var/lib/fanout/password
```

输入 `f` 可打开管理菜单。

## 使用

### 创建出口与 Listener

1. 在 Web 界面点「新建节点」，由 3m-ui QuickCreate 生成协议配置和端口。
2. 点「新建出口」，选择地区、数量和 Listener 模板。
3. fanout 并行拉起隧道，再为每条出口复制 Listener、合并代理用户并写入 Mihomo 路由。
4. 在节点详情中可以改端口、备注、启停、代理用户及绑定出口。

fanout 创建的代理用户带有 `fanout:` 备注。删除 Listener 时，只清理带此标记且不再绑定其他 Listener 的用户。

### Mihomo 服务端路由

绑定 Listener 时，fanout 通过 API 创建或更新如下出站与规则：

```yaml
proxies:
  - name: fanout-jp-home
    type: socks5
    server: 127.0.0.1
    port: 23000
    username: <该出口的SOCKS5用户名>
    password: <该出口的SOCKS5密码>

rules:
  - IN-PORT,10001,fanout-jp-home
  - MATCH,DIRECT
```

`IN-PORT` 规则会放在 `MATCH` 前。fanout 只管理 `fanout-` 前缀的出站和对应规则；被代理组、rule-provider、`dialer-proxy` 或其他规则引用的旧出站不会被删除。

### 订阅

Web 界面的「订阅」提供两类地址：

```text
通用订阅：
http://<服务器>:<端口>/<访问路径>/sub?token=<口令>

Mihomo YAML：
http://<服务器>:<端口>/<访问路径>/sub?token=<口令>&target=mihomo
```

可用参数：

| 参数 | 说明 |
| --- | --- |
| `target=base64` | 默认，整份链接文本做 base64 |
| `target=links` | 明文分享链接 |
| `target=mihomo` | Mihomo `proxies` YAML；`target=yaml` 等价 |
| `bound=0` | 包含未绑定出口的 Listener；默认只包含已绑定出口者 |
| `host=<地址>` | 覆盖分享配置中的连接主机；默认使用母机公网地址 |

Mihomo 输出是适用于订阅/proxy-provider 的 `proxies` 文档，不是包含端口、DNS 和完整规则的独立客户端配置。不同 Listener 的 proxy 名称必须唯一，重复时订阅会返回明确错误。没有可订阅节点时返回 404，避免客户端用空正文清掉旧节点。

订阅地址无需 Web 登录，**token 就相当于密码**。泄露后请在界面点「换一串口令」。

## 运维

```bash
f info       # 查看连接信息与 3m-ui 配置状态
f list       # 查看隧道
f restart    # 重启
f log        # 跟踪日志
f uninstall  # 卸载
```

隧道状态保存在 `/var/lib/fanout/state.json`，重启后自动恢复。健康检查每 10 秒比对实际出口 IP，连续两次异常会自动重连并同步 3m-ui 路由。

复刻版不会默认从上游仓库更新，避免误装不支持 3m-ui 的原版：

- Web/API 在线更新需要设置 `FANOUT_UPDATE_REPO=<owner>/<repo>`。
- 命令行更新使用 `REPO=<owner>/<repo> f update`。

## 已知限制

- 仅支持 Linux；Windows 11 可用于浏览管理页面或编辑源码，不能直接运行 netns 数据面。
- 仅支持 3m-ui，不再支持 3x-ui、xray-cf-lite 或内置 Xray。
- 3m-ui 必须与 fanout 同机，Listener 必须是单端口。
- 分享导出会临时覆盖 Listener 的 `PublicHost`，完成后立即恢复；恢复失败会返回明确错误。
- 管理界面自身没有 HTTPS，公网部署建议增加反向代理与 TLS。
- VPN Gate 节点由志愿者提供，可用性与速度不稳定。

## 许可与来源

[MIT](LICENSE)。

- 原项目：[byJoey/fanout](https://github.com/byJoey/fanout)
- 面板：[kazeyukiro/3m-ui](https://github.com/kazeyukiro/3m-ui)
- 节点：[VPN Gate](https://www.vpngate.net/)（筑波大学学术实验项目）

请遵守 VPN Gate、3m-ui 的条款以及所在地法律法规。
