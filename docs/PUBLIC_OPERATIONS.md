# 域名、备份与恢复

## 安装完成后绑定域名

把面板域名的 A 记录指向 VPS 的公网 IPv4。可选的代理域名也应解析到同一个 IPv4。确保没有指向其他服务的 AAAA 记录。如果首装时未创建 `install.env`，先从 `config/install.example.env` 复制。填写安装时的 IPv4 和 UDP 端口，再填写 `PANEL_HOST` 及可选的 `PROXY_HOST`，然后在项目根目录运行：

```bash
sudo bash install.sh bind-domain --config install.env
```

输入 `BIND` 后，脚本为面板域名签发证书，部署域名入口并验证原 IP 与域名两处 HTTPS。原 IP 上已有的订阅链接仍有效。从域名面板新导出的订阅可以使用 `PROXY_HOST` 作为服务器地址，仍以原公网 IPv4 验证 Hysteria2 证书。旧配置继续使用 IP，账号凭据和流量记录从原数据库读取。域名和 IP 的浏览器会话各自登录。

从外部设备分别访问面板 IP 和域名。可在原 IP 面板和域名面板分别导出临时账号的配置，再运行 `verify.sh external` 和 `verify.sh external --domain`。两次均应通过。首版支持添加一组域名。

## 备份与恢复

```bash
sudo bash install.sh backup /root/hy2-backup.tar.gz
sudo bash install.sh restore /root/hy2-backup.tar.gz
```

备份含 SQLite 一致性快照、代理配置、面板密钥和 API 凭据。备份文件只能新建，默认权限为 0600。请将备份复制到仅你可访问的存储。续期所需证书状态由目标安装维护，域名入口可在目标机器重新绑定。

首版恢复要求目标已安装本版本，并使用**相同的公网 IPv4 和代理 UDP 端口**。这适用于同一 VPS 的恢复或公网 IP 可以迁移的替换主机。不同公网 IP 的迁移尚未实现。恢复需要输入 `RESTORE`，会短暂停止相关服务并重载代理。脚本保留恢复前的数据，检查代理认证及面板健康，失败时尝试回退。恢复会使原面板登录会话失效。

恢复验收应在隔离 VPS 上执行。先备份，再仅修改一个临时账号，恢复后重新登录，核对账号状态、已有订阅、原凭据和流量记录。

## 续期和重启验收

通过 `systemctl list-timers hy2-lite-renew.timer` 查看下次检查时间，通过 `sudo systemctl start hy2-lite-renew.service` 执行正常的续期检查。提前执行时，Certbot 可能判断证书尚无需续期。要验证实际加载新证书，应在干净测试 VPS 上记录 IP 及域名证书指纹，等待证书进入续期窗口，再比较续期后的指纹并重新运行本机和公网验收。真实重启后也要重跑验收。
