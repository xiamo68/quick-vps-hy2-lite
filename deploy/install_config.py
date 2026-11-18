"""Render settings for an installation that already owns its system paths."""

import argparse
import grp
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

from preflight import load_config


def write_once(path, content, mode=0o600, group=None):
    if path.exists():
        return
    fd, filename = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            os.fchmod(output.fileno(), mode)
            if group:
                os.fchown(output.fileno(), -1, grp.getgrnam(group).gr_gid)
        os.replace(filename, path)
    finally:
        Path(filename).unlink(missing_ok=True)


def documents(address, port, token, password):
    endpoint = {"host": address, "port": port, "sni": address}
    control = "hy2-lite-health-probe"
    probe_host, probe_port = "127.0.0.2", 18772
    tls = "/etc/hy2-lite/tls/current"
    return (
        {
            "log": {"level": "warn"},
            "inbounds": [{
                "type": "hysteria2", "tag": "hy2-us", "listen": "0.0.0.0", "listen_port": port,
                "users": [{"name": control, "password": password}],
                "tls": {"enabled": True, "certificate_path": f"{tls}/fullchain.pem",
                        "key_path": f"{tls}/privkey.pem"},
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "dns": {"servers": [{"type": "local", "tag": "system"}]},
            "route": {"rules": [
                {"ip_cidr": [f"{probe_host}/32"], "port": [probe_port], "network": "tcp",
                 "action": "route", "outbound": "direct"},
                {"action": "resolve", "server": "system"},
                {"ip_is_private": True, "action": "reject"},
            ], "final": "direct"},
            "services": [{"type": "api", "tag": "hy2-lite-api", "listen": "127.0.0.1",
                          "listen_port": 18771, "secret": token, "dashboard": False}],
        },
        {"binary": "/opt/hy2-lite/bin/sing-box", "config": "/etc/sing-box/config.json",
         "state": "/var/lib/hy2-lite-operator", "work_directory": "/var/lib/hy2-lite-sing-box",
         "inbound": "hy2-us", "control_user": control, "api_port": 18771, "endpoint": endpoint,
         "probe_host": probe_host, "probe_port": probe_port,
         "api_token_file": "/etc/hy2-lite/api.token",
         "subscription_key_file": "/etc/hy2-lite/subscriptions.fernet-key"},
    )


def render(address, port):
    config = Path("/etc/hy2-lite")
    token_path = config / "api.token"
    write_once(token_path, secrets.token_urlsafe(32) + "\n")
    sing, operator = documents(address, port, token_path.read_text().strip(), secrets.token_urlsafe(32))
    write_once(Path("/etc/sing-box/config.json"), json.dumps(sing) + "\n", 0o640, "sing-box")
    write_once(config / "operator.json", json.dumps(operator) + "\n")
    write_once(config / "web.env", f"HY2_PUBLIC_ORIGIN=https://{address}\n")
    route = subprocess.run(["ip", "-j", "-4", "route", "show", "default"],
                           capture_output=True, text=True, check=True, timeout=5)
    paths = json.loads(route.stdout)
    device = paths[0].get("dev") if paths else None
    arguments = f"--interface {device}" if device and device.isascii() and device.replace("-", "").isalnum() else ""
    write_once(config / "collector.env", f'HY2_INTERFACE_ARGS="{arguments}"\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("settings", "render"))
    parser.add_argument("config", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        settings = load_config(args.config, detect=args.action == "settings")
        if settings.panel_host or settings.proxy_host:
            raise ValueError("Leave domain fields empty for initial installation. Use bind-domain after setup.")
        if args.action == "settings":
            print(f"{settings.public_ipv4} {settings.proxy_port}")
        else:
            render(settings.public_ipv4, settings.proxy_port)
    except (OSError, ValueError, argparse.ArgumentTypeError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
