"""Verify a new HY2 Lite installation locally or from another network."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from deploy.preflight import DEFAULT_PORT, load_config, public_ipv4, udp_port
from hy2_lite.user_ids import is_managed_id


APP = Path("/opt/hy2-lite/current")
DB = Path("/var/lib/hy2-lite/panel.sqlite3")
INSTALLED_SETTINGS = Path("/var/lib/hy2-lite-install/settings")
UNITS = ("sing-box.service", "hy2-lite-web.service", "hy2-lite-edge.service",
         "hy2-lite-collector.service", "hy2-lite-executor.service", "hy2-lite-renew.timer")


class Results:
    def __init__(self):
        self.counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0}

    def add(self, status, message):
        self.counts[status] += 1
        print(f"{status}: {message}", flush=True)

    def finish(self):
        print("Verification summary:", ", ".join(f"{name} {count}" for name, count in self.counts.items()))
        return int(bool(self.counts["FAIL"]))


def run_quiet(command, timeout=10):
    return subprocess.run(command, capture_output=True, timeout=timeout, check=True)


def health(address, *, loopback=False):
    command = ["curl", "-q", "--fail", "--silent", "--noproxy", "*", "--max-time", "8"]
    if loopback:
        command += ["--connect-to", f"{address}:443:127.0.0.1:443"]
    try:
        payload = run_quiet(command + [f"https://{address}/healthz"]).stdout
        return json.loads(payload) == {"status": "ok"}
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def sample_time(db):
    row = db.execute("SELECT at FROM collector_state WHERE id=1").fetchone()
    return row[0] if row else None


def user_total(db, user):
    record = db.execute("SELECT origin,effective_state FROM users WHERE user_id=?", (user,)).fetchone()
    if record != ("managed", "enabled"):
        raise ValueError("Use an enabled temporary managed account.")
    total, = db.execute(
        """SELECT coalesce(sum(bytes), 0) FROM (
            SELECT upload + download AS bytes FROM traffic_lifetime WHERE scope='user' AND subject=?
            UNION ALL
            SELECT upload + download FROM traffic_hourly WHERE scope='user' AND subject=?
        )""", (user, user)).fetchone()
    return total


def check_collector(results, user, wait_seconds):
    try:
        with closing(sqlite3.connect(f"{DB.as_uri()}?mode=ro", uri=True, timeout=3)) as db:
            start = sample_time(db)
            before = user_total(db, user) if user else None
            if user:
                print(f"Traffic baseline recorded. Start the external test within {wait_seconds} seconds.", flush=True)
            deadline = time.monotonic() + (wait_seconds if user else 20)
            advanced = observed = False
            while time.monotonic() < deadline:
                current = sample_time(db)
                advanced = current is not None and (start is None or current > start)
                observed = user is not None and user_total(db, user) > before
                if advanced and (not user or observed):
                    break
                time.sleep(1)
        results.add("PASS" if advanced else "FAIL", "Collector wrote a new sample" if advanced else
                    "No new samples. Check the collector and native API.")
        if user:
            results.add("PASS" if observed else "FAIL", "Temporary account traffic recorded" if observed else
                        "No new traffic for this account. Check the test account and collector events.")
    except (OSError, sqlite3.Error):
        results.add("FAIL", "Could not read the collector database. Check the installation path and permissions.")
    except ValueError as exc:
        results.add("FAIL", str(exc))


def local(args, results):
    if os.name != "posix" or os.geteuid() != 0:
        results.add("FAIL", "Run sudo bash verify.sh local on the VPS.")
        return
    for unit in UNITS:
        try:
            run_quiet(["systemctl", "is-active", "--quiet", unit])
            run_quiet(["systemctl", "is-enabled", "--quiet", unit])
        except (OSError, subprocess.SubprocessError):
            results.add("FAIL", f"{unit} is inactive or disabled at boot")
        else:
            results.add("PASS", f"{unit} is running and enabled at boot")
    ok = health(args.settings.public_ipv4, loopback=True)
    results.add("PASS" if ok else "FAIL", "Local HTTPS certificate and panel health" if ok else
                "Local HTTPS check failed. Check the IP address, certificate, and web service.")
    helper = Path(__file__).with_name("check_install_probe.py")
    # Share the operator lock since the health probe uses a reserved local port.
    command = ["flock", "-w", "15", "/var/lib/hy2-lite-operator/jobs.lock", sys.executable, "-B", str(helper)]
    try:
        subprocess.run(command, env={**os.environ, "PYTHONPATH": str(APP)}, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40)
    except (OSError, subprocess.SubprocessError):
        results.add("FAIL", "Local proxy authentication failed. Check the executor lock, proxy, and certificate.")
    else:
        results.add("PASS", "Dedicated account authenticated over local Hysteria2")
    check_collector(results, args.watch_user, args.wait)


def load_outbound(path, address, port, *, certificate_ip=None):
    certificate_ip = certificate_ip or address
    try:
        with path.open("rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or (os.name == "posix" and metadata.st_mode & 0o077):
                raise ValueError
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError
        item, = json.loads(data)["outbounds"]
        tls = item["tls"]
        if (item["type"] != "hysteria2" or item["server"] != address or item["server_port"] != port
                or not isinstance(item["password"], str) or not item["password"]
                or tls["enabled"] is not True or tls.get("insecure", False) is not False
                or tls["server_name"] != certificate_ip):
            raise ValueError
        return {"type": "hysteria2", "server": address, "server_port": port, "password": item["password"],
                "tls": {"enabled": True, "server_name": certificate_ip}}
    except (OSError, KeyError, TypeError, ValueError):
        raise ValueError("Use the temporary account sing-box JSON exported from this VPS. On Linux or WSL, set file permissions to 600.") from None


def proxy_https_request(binary, outbound):
    with TemporaryDirectory(prefix="hy2-verify-") as folder:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = Path(folder) / "client.json"
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump({"inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": port}],
                       "outbounds": [outbound]}, stream)
        with subprocess.Popen([binary, "-D", folder, "-c", str(config), "run"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as client:
            try:
                deadline = time.monotonic() + 5
                while client.poll() is None and time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("The external test client could not start.")
                run_quiet(["curl", "-q", "--fail", "--silent", "--max-time", "12", "--noproxy", "",
                           "--proxy", f"http://127.0.0.1:{port}", "--output", os.devnull,
                           "https://example.com/"], timeout=14)
            finally:
                if client.poll() is None:
                    client.terminate()
                    try:
                        client.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        client.kill()
                        client.wait()


def external(args, results):
    address = args.settings.public_ipv4
    panel = args.settings.panel_host if args.domain else address
    if panel is None:
        results.add("FAIL", "Set PANEL_HOST in the configuration for domain verification.")
        return
    ok = health(panel)
    results.add("PASS" if ok else "FAIL", "Public HTTPS certificate and panel health" if ok else
                "Public HTTPS check failed. Check the address, certificate, and TCP port 443.")
    if args.client_config is None:
        results.add("SKIPPED", "Pass the temporary account sing-box JSON with --client-config to test proxy access.")
        return
    binary = shutil.which(args.sing_box)
    if not binary:
        results.add("FAIL", "sing-box was not found. Set its path with --sing-box.")
        return
    try:
        endpoint = (args.settings.proxy_host or address) if args.domain else address
        outbound = load_outbound(args.client_config, endpoint, args.settings.proxy_port,
                                 certificate_ip=address)
        proxy_https_request(binary, outbound)
    except (ValueError, RuntimeError) as exc:
        results.add("FAIL", str(exc))
    except (OSError, subprocess.SubprocessError):
        results.add("FAIL", "Hysteria2 request failed. Check the UDP port, test account, and proxy egress.")
    else:
        results.add("PASS", "Temporary account reached the HTTPS test site over public Hysteria2")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    server = modes.add_parser("local")
    client = modes.add_parser("external")
    for mode in (server, client):
        mode.add_argument("--config", type=Path)
    server.add_argument("--watch-user")
    server.add_argument("--wait", type=int, default=60)
    client.add_argument("--client-config", type=Path)
    client.add_argument("--sing-box", default="sing-box")
    client.add_argument("--domain", action="store_true")
    client.add_argument("--public-ipv4")
    client.add_argument("--proxy-port", type=udp_port)
    args = parser.parse_args()
    if args.mode == "local" and (not 10 <= args.wait <= 300 or
            args.watch_user and not is_managed_id(args.watch_user)):
        parser.error("Provide a temporary managed user ID and a wait time of 10 to 300 seconds.")
    try:
        if args.mode == "local" and args.config is None:
            ip, port = INSTALLED_SETTINGS.read_text().split()
            args.settings = argparse.Namespace(public_ipv4=public_ipv4(ip), proxy_port=udp_port(port))
        elif args.mode == "external" and args.public_ipv4 is not None:
            if args.config or args.domain:
                raise ValueError("Use --config for domain verification or --public-ipv4 for IP verification.")
            args.settings = argparse.Namespace(public_ipv4=public_ipv4(args.public_ipv4),
                                               proxy_port=args.proxy_port or DEFAULT_PORT)
        else:
            if args.mode == "external" and args.proxy_port is not None:
                raise ValueError("--proxy-port requires --public-ipv4.")
            args.settings = load_config(args.config)
    except (OSError, ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))
    results = Results()
    (local if args.mode == "local" else external)(args, results)
    return results.finish()


if __name__ == "__main__":
    raise SystemExit(main())
