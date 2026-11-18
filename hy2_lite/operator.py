"""Local operator entry point for one approved job, with real Hysteria2 probes."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import tempfile
from threading import Thread
import time

from cryptography.fernet import Fernet

from .collector import NativeAPI
from .config_transaction import ConfigTransaction, RecoveryRequired, locked
from .database import connect
from .jobs import JobRunner
from .original_subscriptions import is_original_id
from .subscriptions import Endpoint


def read_settings(path):
    path = path.resolve(strict=True)
    if path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Operator settings must not be writable by group or others")
    return json.loads(path.read_bytes())


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextmanager
def probe_target(port=0, host="127.0.0.1"):
    expected = secrets.token_hex(16).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(expected)))
            self.end_headers()
            self.wfile.write(expected)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer((host, port), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, expected
        finally:
            server.shutdown()
            thread.join()


def probe(binary, endpoint, password, destination, expected, trust_path=None, *, target_host="127.0.0.1"):
    port = free_port()
    tls = {"enabled": True, "server_name": endpoint.sni}
    if trust_path:
        tls["certificate_path"] = str(trust_path)
    with tempfile.TemporaryDirectory(prefix="hy2-operator-probe-") as folder:
        config = Path(folder) / "client.json"
        config.write_text(json.dumps({
            "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "hysteria2", "server": endpoint.host,
                           "server_port": endpoint.port, "password": password, "tls": tls}],
        }), encoding="utf-8")
        with subprocess.Popen([binary, "run", "-D", folder, "-c", str(config)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as client:
            try:
                deadline = time.monotonic() + 4
                while client.poll() is None and time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RecoveryRequired("Authentication probe client failed to start")
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    connection.request("GET", f"http://{target_host}:{destination}/")
                    response = connection.getresponse()
                    if response.status == 200:
                        if response.read(len(expected) + 1) != expected:
                            raise RecoveryRequired("Probe received an unexpected response")
                        return True
                    if response.status == 502:
                        return False
                    raise RecoveryRequired("Probe returned an unexpected HTTP status")
                except (ConnectionResetError, http.client.RemoteDisconnected):
                    return False
                finally:
                    connection.close()
            finally:
                if client.poll() is None:
                    client.terminate()
                    try:
                        client.wait(3)
                    except subprocess.TimeoutExpired:
                        client.kill()


def run_job(database, settings, job_id, *, reload_process=None, confirm_original=None):
    binary = str(Path(settings.get("binary", "/usr/bin/sing-box")).resolve(strict=True))
    live = Path(settings["config"]).absolute()
    if live.is_symlink():
        raise ValueError("Operator configuration must not be a symlink")
    state = Path(settings["state"]).resolve()
    directory = live.parent
    work = Path(settings["work_directory"]).resolve(strict=True)
    # The known installation has one config file. Reject layouts requiring
    # configuration merging until the complete candidate can be validated.
    if {path.name for path in directory.glob("*.json")} != {live.name}:
        raise ValueError("Expected exactly one sing-box JSON configuration")
    tag = settings.get("inbound", "hy2-us")
    endpoint = Endpoint(**settings["endpoint"])
    local_endpoint = Endpoint("127.0.0.1", endpoint.port, endpoint.sni)
    cipher = Fernet(Path(settings["subscription_key_file"]).read_bytes().strip())
    api = NativeAPI(settings.get("api_port", 18771),
                    Path(settings["api_token_file"]).read_text(encoding="ascii").strip(), tag)
    control_name = settings["control_user"]
    if not control_name.startswith("hy2-"):
        raise ValueError("Configure a dedicated non-original probe account")

    def check(candidate):
        subprocess.run([binary, "check", "-D", str(work), "-c", str(candidate)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)

    def reload():
        try:
            epoch = api.epoch()
        except (OSError, ValueError, http.client.HTTPException):
            epoch = None
        if reload_process is None:
            subprocess.run(["systemctl", "reload", "sing-box.service"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        else:
            reload_process.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if api.epoch() != epoch:
                    return
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise RecoveryRequired("sing-box native API did not confirm a new instance")

    def users(blob):
        inbound, = [item for item in json.loads(blob)["inbounds"]
                    if item.get("type") == "hysteria2" and item.get("tag") == tag]
        return {item["name"]: item["password"] for item in inbound["users"]}

    def verify(expected, previous):
        current, old = users(expected), users(previous)
        target_host = settings.get("probe_host", "127.0.0.1")
        with probe_target(settings.get("probe_port", 0), target_host) as (target, body):
            def works(password):
                return probe(binary, local_endpoint, password, target, body, settings.get("probe_ca_file"),
                             target_host=target_host)

            if not current.get(control_name) or not works(current[control_name]):
                raise RecoveryRequired("Dedicated control account failed")
            for name in current.keys() ^ old.keys():
                password = current[name] if name in current else old[name]
                if works(password) != (name in current):
                    raise RecoveryRequired("Target account authentication did not match requested state")

    tx = ConfigTransaction(live, state, tag, check, reload, verify)
    if not database.is_file():
        raise ValueError("Initialize the database first")
    with connect(database) as db:
        job = db.execute("SELECT user_id, action FROM config_jobs WHERE id=?", (job_id,)).fetchone()
    if job is None or job[0] == control_name:
        raise ValueError("Unknown job or protected probe account")
    if is_original_id(job[0]) and confirm_original != f"{job[1]}:{job[0]}":
        raise ValueError("Original account requires --confirm-original ACTION:USER_ID")
    return JobRunner(database, tx, cipher, endpoint).run(job_id)


def execute_next(database, settings, *, execute=run_job):
    """Dispatch only requests explicitly confirmed for immediate execution."""
    with locked(Path(settings["state"]).resolve(strict=True) / "dispatch.lock"):
        with connect(database) as db:
            if db.execute("SELECT 1 FROM config_jobs WHERE needs_review=1 OR "
                          "(status='running' AND execute_now=0)").fetchone():
                return False
            job = db.execute(
                "SELECT id, action, user_id FROM config_jobs "
                "WHERE execute_now=1 AND status IN ('running','pending') "
                "ORDER BY status='running' DESC, created_at, id LIMIT 1"
            ).fetchone()
        if job is None:
            return False
        job_id, action, user_id = job
        try:
            if not re.fullmatch(r"[a-f0-9]{32}", job_id):
                raise ValueError("Invalid immediate job ID")
            execute(database, settings, job_id, confirm_original=f"{action}:{user_id}")
        except Exception:
            # Preserve unfinished transactions for manual recovery.
            with connect(database, write=True) as db:
                db.execute("UPDATE config_jobs SET needs_review=(status='running'), "
                           "status=CASE WHEN status='pending' THEN 'failed' ELSE status END WHERE id=?",
                           (job_id,))
            print("Account execution failed; inspect job status", flush=True)
        return True
