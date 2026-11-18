# 安装验收

验收在独立测试 VPS 上进行。服务器本机检查读取安装保存的公网 IPv4 和端口。外部设备使用不同网络，例如连接手机热点的电脑。

## 服务器检查

在 VPS 的项目根目录执行：

```bash
sudo bash verify.sh local
```

脚本检查服务运行状态和开机自启设置，通过回环验证公网 IP 证书、面板健康、专用账号认证，以及采集器是否写入新样本。真实重启后的恢复需要在维护窗口另行检查。

## 从外部验证认证和按用户入库

1. 从外部浏览器打开安装输出的 HTTPS 地址，确认浏览器信任证书并能登录。创建一个临时托管账号，等网页显示「已生效」，记下用户 ID，并从订阅页导出 **sing-box JSON**。
2. 回到 VPS，在同一个项目目录启动观测。把下方示例 ID 替换为临时账号 ID：

   ```bash
   sudo bash verify.sh local --watch-user h2-test --wait 120
   ```

3. 等 VPS 输出 `Traffic baseline recorded`，在外部 Linux 或 WSL 设备的项目根目录执行以下命令。外部设备需要 Python 3、curl 和 sing-box。把导出的文件保存到本机私有目录：

   ```bash
   chmod 600 ~/hy2-verify-client.json
   bash verify.sh external --public-ipv4 VPS公网IPv4 --client-config ~/hy2-verify-client.json
   ```

   自定义 UDP 端口时，追加 `--proxy-port`。也可以用 `--config install.env` 提供目标地址和端口。若 sing-box 不在 PATH，用 `--sing-box /path/to/sing-box` 指定。外部脚本验证公开 HTTPS 和临时账号代理认证，测试客户端和临时配置会自动清理。
4. 外部设备应显示 `Temporary account reached the HTTPS test site over public Hysteria2`，VPS 应显示 `Temporary account traffic recorded`。观察窗口内只用该账号执行这次验收。
5. 如需验证账号生命周期，可在隔离 VPS 上通过面板禁用该临时账号，等状态生效后重新跑外部命令，预期 HTTPS 面板正常但代理测试失败。重新启用后，用同一份 JSON 复验应成功。结束后在面板删除临时账号并确认已生效，移除本地导出文件。

只检查公网 HTTPS 时可运行 `bash verify.sh external --public-ipv4 VPS公网IPv4`，代理会列为「未验证」。失败返回 1，参数或配置错误返回 2。返回 0 表示本次执行的检查未失败，发布验收仍需完成所有标为「未验证」的必测项。
