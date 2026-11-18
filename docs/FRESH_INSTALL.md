# 全新 VPS 安装

阶段 2 实现了安装流程，干净 Ubuntu 24.04 amd64 VPS 上的公开证书签发和外部认证仍待验收。使用独立测试机。

在云控制台确认 VPS 的公网 IPv4，放行 TCP 80/443 和所选 UDP 代理端口，保留 SSH 的访问规则。安装脚本在新主机上配置服务，不代改云防火墙。公网 IPv4 会用于 HTTPS 和代理订阅。

解压后，在项目根目录依次执行：

```bash
bash check.sh
sudo bash install.sh
sudo bash verify.sh local
```

脚本通过 HTTPS 查询 VPS 的出站公网 IPv4。若机器位于 NAT 后且出站地址与云控制台的入站地址不同，或自动检测失败，复制 `config/install.example.env` 为 `install.env` 并填写公网 IPv4。通常无需配置文件。核对地址后输入 `INSTALL`，在 SSH 终端设置管理员 `admin` 密码（至少 8 个字符）。安装结束后可按[运维指南](PUBLIC_OPERATIONS.md)绑定域名。

通过安装内置的健康检查后，打开结果中的 `https://公网IPv4`。脚本在本机验证 HTTPS 和专用代理账号。再按[安装验收指南](VERIFY.md)检查外部客户端和流量入库。

安装完成时，终端会集中显示面板 URL、用户名 `admin`，并提示使用刚才输入的密码。密码输入时隐藏，不会打印到终端。新账号的 ID 由显示名称生成，例如「测试1」对应 `h2-测试1`，重名时加数字后缀。编辑显示名称时 ID 保持稳定。

安装失败会提示中断阶段。修正问题后，用同一份配置再次运行，安装会复用已生成的证书状态、密钥和管理员记录。安装完成后重复运行会直接返回已安装状态。已有服务或安装路径会阻止首次安装。不要删除安装状态来强行覆盖现有配置。

续期定时器每天检查两次。续期后把同一份新证书发布给 Caddy 和 sing-box，并重载服务。保持 TCP 80 的 ACME 验证路径可用。证书及私钥保存在服务器上。

开发验证可在 Linux 环境运行 `PYTHONPATH=.:deploy python3 -B tests/smoke_fresh_proxy.py /path/to/sing-box`。脚本使用临时证书和回环监听验证生成的代理配置、认证和私网访问限制。
