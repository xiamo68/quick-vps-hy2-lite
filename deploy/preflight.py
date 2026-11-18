"""Check prerequisites for a fresh deployment without changing the host."""

import argparse
import ipaddress
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
from urllib.request import ProxyHandler, build_opener, urlopen


INSTALL_PATHS = (
    "/etc/sing-box", "/etc/caddy", "/etc/hy2-lite",
    "/opt/hy2-lite", "/var/lib/hy2-lite", "/var/lib/hy2-lite-operator",
    "/var/lib/hy2-lite-install", "/var/lib/hy2-lite-acme",
    "/var/lib/hy2-lite-edge", "/var/lib/hy2-lite-sing-box",
)
SETTINGS = {"PUBLIC_IPV4", "PROXY_PORT", "PANEL_HOST", "PROXY_HOST"}
MIN_FREE = 2 * 1024 ** 3
DEFAULT_PORT = 24443
DEFAULT_CONFIG = Path("install.env")


def read_config(path):
    values = {}
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in SETTINGS or key in values:
            raise ValueError(f"Config line {number} must use a unique, supported KEY=value entry.")
        values[key] = value.strip()
    return argparse.Namespace(
        public_ipv4=public_ipv4(values.get("PUBLIC_IPV4", "")),
        proxy_port=udp_port(values.get("PROXY_PORT", str(DEFAULT_PORT))),
        panel_host=hostname(values["PANEL_HOST"]) if values.get("PANEL_HOST") else None,
        proxy_host=hostname(values["PROXY_HOST"]) if values.get("PROXY_HOST") else None,
    )


def public_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        address = None
    if address is None or not address.is_global or address.is_multicast:
        raise ValueError("PUBLIC_IPV4 must be a public IPv4 address. Check your cloud console.")
    return str(address)


def detect_ipv4():
    try:
        # Use the machine's outward connection, not an HTTP proxy set in its environment.
        with build_opener(ProxyHandler({})).open("https://api.ipify.org", timeout=8) as response:
            return public_ipv4(response.read(64).decode("ascii").strip())
    except (OSError, ValueError):
        raise ValueError("Could not detect the public IPv4 address. Check outbound HTTPS or set PUBLIC_IPV4 in install.env.") from None


def load_config(path=None, *, detect=False):
    if path is not None:
        return read_config(path)
    if DEFAULT_CONFIG.exists():
        return read_config(DEFAULT_CONFIG)
    if not detect:
        raise ValueError("Provide --config or a public IPv4 address.")
    return argparse.Namespace(public_ipv4=detect_ipv4(), proxy_port=DEFAULT_PORT,
                              panel_host=None, proxy_host=None)


def hostname(value):
    normalized = value.lower().removesuffix(".")
    labels = normalized.split(".")
    if (len(labels) < 2 or labels[-1].isdigit() or len(normalized) > 253
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise argparse.ArgumentTypeError("Enter a fully qualified domain name, such as panel.example.com.")
    return normalized


def udp_port(value):
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("The UDP port must be between 1 and 65535.")


def port_conflicts(listeners, proxy_port):
    expected = {("tcp", 80), ("tcp", 443), ("tcp", 18770), ("tcp", 18771), ("tcp", 18772), ("udp", proxy_port)}
    occupied = set()
    for line in listeners.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            _, _, port = fields[4].rpartition(":")
            if port.isdecimal():
                occupied.add((fields[0], int(port)))
    return sorted(expected & occupied)


def inspect_host(args):
    if platform.system() != "Linux":
        return ["Run this check on the target Ubuntu 24.04 VPS."], []
    errors, unverified = [], []
    try:
        release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator:
                release[key] = value.strip('"')
    except OSError:
        release = {}
    if (release.get("ID"), release.get("VERSION_ID")) != ("ubuntu", "24.04"):
        errors.append("This release requires Ubuntu 24.04.")
    if not Path("/run/systemd/system").is_dir():
        errors.append("The VPS must be running systemd.")
    if platform.machine() != "x86_64":
        errors.append("This release requires an x86_64 (amd64) VPS.")
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            unverified.append("Installation requires root privileges. Check that your account can use sudo.")
        else:
            errors.append("Use an administrator account. The current account is not root and sudo was not found.")
    for directory in ("/opt", "/var", "/tmp"):
        try:
            if shutil.disk_usage(directory).free < MIN_FREE:
                errors.append(f"{directory} has less than 2 GiB free. Free up disk space and retry.")
        except OSError:
            errors.append(f"Could not check disk space for {directory}.")
    if not shutil.which("apt-get"):
        errors.append("apt-get was not found. Use a standard Ubuntu 24.04 image.")
    else:
        try:
            with urlopen("https://archive.ubuntu.com/ubuntu/dists/noble/InRelease", timeout=8) as response:
                response.read(1)
        except OSError:
            errors.append("Could not reach the Ubuntu package repository. Check outbound HTTPS, DNS, and the system clock.")

    for path in map(Path, INSTALL_PATHS):
        if path.exists() or path.is_symlink():
            errors.append(f"Installation path already exists: {path}. Use a fresh VPS.")
    try:
        listeners = subprocess.run(["ss", "-H", "-lntu"], check=True, capture_output=True,
                                   text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        errors.append("Could not list local ports. Check iproute2 and ss.")
    else:
        for protocol, port in port_conflicts(listeners, args.proxy_port):
            errors.append(f"Port already in use: {port}/{protocol}.")

    for host in sorted({args.panel_host, args.proxy_host} - {None}):
        try:
            result = subprocess.run(["getent", "ahostsv4", host], check=True, capture_output=True,
                                    text=True, timeout=5)
            addresses = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
            if addresses != {args.public_ipv4}:
                errors.append(f"{host} does not resolve locally to PUBLIC_IPV4. Check its A record.")
        except (OSError, subprocess.SubprocessError):
            errors.append(f"Could not resolve {host}. Check its A record.")
    return errors, unverified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    options = parser.parse_args()
    try:
        args = load_config(options.config, detect=True)
    except FileNotFoundError:
        parser.error("Config file not found. Copy config/install.example.env and set PUBLIC_IPV4.")
    except (OSError, ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))

    print(f"Public IPv4: {args.public_ipv4} / Proxy port: {args.proxy_port}/UDP")
    errors, unverified = inspect_host(args)
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("PASS: Local installation prerequisites")
    for item in unverified:
        print(f"NOTE: {item}")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
