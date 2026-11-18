#!/usr/bin/env bash
set -eu

python3 -u - "$@" <<'PY'
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

HOST = "127.0.0.1"
BINARY = os.environ.get("HY2_AUDIT_BINARY", "/usr/bin/sing-box")
INTERVAL = b"\x08\x80\xca\xb5\xee\x01"  # protobuf field 1, 500 ms in nanoseconds


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            raise EOFError("stream ended early")
        data.extend(part)
    return bytes(data)


def fields(data):
    position = 0

    def varint():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError("invalid protobuf varint")

    while position < len(data):
        key = varint()
        field, wire = key >> 3, key & 7
        if wire == 0:
            yield field, varint()
        elif wire == 2:
            size = varint()
            end = position + size
            if end > len(data):
                raise ValueError("truncated protobuf field")
            yield field, data[position:end]
            position = end
        else:
            raise ValueError(f"unexpected protobuf wire type: {wire}")


def frame(response):
    flag, size = struct.unpack(">BI", read_exact(response, 5))
    if flag != 0 or size > 4 * 1024 * 1024:
        raise RuntimeError(f"unexpected gRPC-Web frame: flag={flag}, bytes={size}")
    return read_exact(response, size)


def open_rpc(stack, port, method, secret=None):
    connection = stack.enter_context(closing(http.client.HTTPConnection(HOST, port, timeout=8)))
    headers = {"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"}
    if secret:
        headers["Authorization"] = "Bearer " + secret
    body = struct.pack(">BI", 0, len(INTERVAL)) + INTERVAL
    connection.request("POST", "/daemon.StartedService/" + method, body, headers)
    response = stack.enter_context(closing(connection.getresponse()))
    if response.status != 200:
        raise RuntimeError(f"{method}: HTTP {response.status}")
    return response


def read_connections(response, records):
    batch = list(fields(frame(response)))
    for field, payload in batch:
        if field != 1:
            continue
        event = dict(fields(payload))
        if 3 not in event:
            continue
        conn = dict(fields(event[3]))
        identity = conn[1]
        if conn.get(2) != b"hy2-audit":
            raise RuntimeError("unexpected inbound in connection event")
        records[identity] = (
            conn.get(10, b"").decode(),
            conn.get(5, b"").decode(),
            conn.get(16, 0),
            conn.get(17, 0),
            event.get(1) == 2 or bool(conn.get(13)),
        )
    return any(field == 2 and payload == 1 for field, payload in batch)


class TcpTarget(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        with self.request.makefile("rb") as stream:
            try:
                header = read_exact(stream, 4)
            except EOFError:
                return  # The HUP test intentionally interrupts an idle connection.
            up, down = struct.unpack(">HH", header)
            if up == down == 0:
                self.request.sendall(b"R")
                try:
                    if stream.read(1) == b"Q":
                        self.request.sendall(b"E")
                except (OSError, TimeoutError):
                    pass
                return
            read_exact(stream, up)
            self.request.sendall(b"T" * down)


class UdpTarget(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        down = struct.unpack(">H", data[:2])[0]
        sock.sendto(b"U" * down, self.client_address)


def start_target(stack, server_type, handler):
    server = stack.enter_context(server_type((HOST, 0), handler))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(server.shutdown)
    return server.server_address[1]


def stop_child(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def spawn(stack, directory, name, config):
    path = directory / f"{name}.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    log = stack.enter_context((directory / f"{name}.log").open("w+"))
    process = subprocess.Popen(
        [BINARY, "run", "-D", str(directory), "-c", str(path)],
        stdin=subprocess.DEVNULL, stdout=log, stderr=log,
    )
    stack.callback(stop_child, process)
    return process, log


def wait_listener(process, log, port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection((HOST, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    log.seek(0)
    raise RuntimeError(f"test listener {port} did not start\n{log.read()[-2000:]}")


def socks_request(stream, control, command, port):
    control.sendall(b"\x05\x01\x00")
    if read_exact(stream, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting failed")
    control.sendall(b"\x05" + bytes([command]) + b"\x00\x01"
                    + socket.inet_aton(HOST) + struct.pack(">H", port))
    reply = read_exact(stream, 4)
    if reply != b"\x05\x00\x00\x01":
        raise RuntimeError(f"SOCKS request failed: {reply.hex()}")
    address, relay_port = struct.unpack(">4sH", read_exact(stream, 6))
    return socket.inet_ntoa(address), relay_port


def tcp_flow(proxy, target, up, down):
    with socket.create_connection((HOST, proxy), timeout=5) as control:
        with control.makefile("rb") as stream:
            socks_request(stream, control, 1, target)
            control.sendall(struct.pack(">HH", up, down) + b"A" * up)
            if read_exact(stream, down) != b"T" * down:
                raise RuntimeError("TCP payload mismatch")
    return up + 4, down


def udp_flow(proxy, target, up, down):
    with socket.create_connection((HOST, proxy), timeout=5) as control:
        with control.makefile("rb") as stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            relay_host, relay_port = socks_request(stream, control, 3, 0)
            if relay_host not in {HOST, "0.0.0.0"}:
                raise RuntimeError("SOCKS UDP relay is outside the test loopback")
            udp.settimeout(5)
            udp.connect((HOST, relay_port))
            header = b"\x00\x00\x00\x01" + socket.inet_aton(HOST) + struct.pack(">H", target)
            udp.send(header + struct.pack(">H", down) + b"B" * up)
            if udp.recv(65535) != header + b"U" * down:
                raise RuntimeError("UDP payload mismatch")
    return up + 2, down


def proxy_totals(api_port, secret):
    with ExitStack() as stack:
        response = open_rpc(stack, api_port, "SubscribeStatus", secret)
        status = dict(fields(frame(response)))
    if not status.get(5):
        raise RuntimeError("native API reports that traffic tracking is unavailable")
    return status.get(8, 0), status.get(9, 0)


def auth_test(directory, config, server, api_port, secret, users, probe):
    live = directory / "server.json"
    candidate = directory / "candidate.json"
    stable, second = users
    added = {"name": "audit-c", "password": secrets.token_urlsafe(24)}

    def apply(active_users):
        config["inbounds"][0]["users"] = active_users
        candidate.write_text(json.dumps(config), encoding="utf-8")
        subprocess.run([BINARY, "check", "-D", str(directory), "-c", str(candidate)],
                       check=True, capture_output=True)
        if proxy_totals(api_port, secret) == (0, 0):
            raise RuntimeError("expected traffic before reloading the isolated instance")
        candidate.replace(live)
        server.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and server.poll() is None:
            try:
                if proxy_totals(api_port, secret) == (0, 0):
                    return
            except (OSError, http.client.HTTPException, EOFError):
                pass
            time.sleep(0.05)
        raise RuntimeError("isolated authentication configuration did not become active")

    probe(stable)
    probe(added, allowed=False)
    apply([stable, second, added])
    probe(stable)
    probe(added)
    print("PASS add: new credentials accepted; control user still authenticates")

    apply([stable, second])
    probe(stable)
    probe(added, allowed=False)
    print("PASS disable: removed credentials rejected; control user still authenticates")

    apply([stable, second, added])
    probe(stable)
    probe(added)
    print("PASS enable: same credentials accepted again")

    apply([stable, second])
    probe(stable)
    probe(second)
    probe(added, allowed=False)
    print("PASS delete: removed credentials rejected; both baseline users still authenticate")


def stress_test(server, log, api_port, secret, proxies, tcp_port, baseline, start_fresh_client):
    burst_count = 64
    with ExitStack() as stack:
        records = {}
        response = open_rpc(stack, api_port, "SubscribeConnections", secret)
        if not read_connections(response, records):
            raise RuntimeError("burst test did not receive an initial snapshot")
        known = set(records)

        def generate(index):
            proxy = proxies[index % 2]
            tcp_flow(proxy, tcp_port, 50 + index, 200 + index)

        def generate_burst():
            with ThreadPoolExecutor(max_workers=8) as workers:
                list(workers.map(generate, range(burst_count)))

        with ThreadPoolExecutor(max_workers=1) as executor:
            work = executor.submit(generate_burst)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                closed = [value for key, value in records.items() if key not in known and value[-1]]
                if len(closed) >= burst_count:
                    break
                try:
                    read_connections(response, records)
                except TimeoutError:
                    break
            work.result()

    expected = sorted(
        ("audit-a" if index % 2 == 0 else "audit-b", "tcp", 54 + index, 200 + index, True)
        for index in range(burst_count)
    )
    if sorted(closed) != expected:
        raise RuntimeError(f"burst: expected {burst_count} attributed flows, captured {len(closed)}")
    totals_before_gap = tuple(baseline[i] + sum(item[i + 2] for item in expected) for i in (0, 1))
    if proxy_totals(api_port, secret) != totals_before_gap:
        raise RuntimeError("proxy totals do not match after burst")
    print(f"PASS live burst attributed {burst_count}/{burst_count} TCP connections")

    # All these connections run while no collector is subscribed.
    gap_count = 1016
    for index in range(gap_count):
        tcp_flow(proxies[index % 2], tcp_port, 37, 61)
    time.sleep(0.5)
    with ExitStack() as stack:
        response = open_rpc(stack, api_port, "SubscribeConnections", secret)
        replay = {}
        if not read_connections(response, replay):
            raise RuntimeError("gap test did not receive a replay snapshot")
    recovered = sum(value[1:] == ("tcp", 41, 61, True) for value in replay.values())
    expected_totals = totals_before_gap[0] + gap_count * 41, totals_before_gap[1] + gap_count * 61
    if proxy_totals(api_port, secret) != expected_totals:
        raise RuntimeError("global proxy totals do not match after collector gap")
    if not 0 < recovered < gap_count:
        raise RuntimeError(f"expected partial per-user replay, recovered {recovered}/{gap_count}")
    print(f"OBSERVED collector gap: recovered {recovered}/{gap_count} closed connections; "
          f"{gap_count - recovered} unavailable for per-user accounting")

    with socket.create_connection((HOST, proxies[0]), timeout=5) as control:
        with control.makefile("rb") as stream:
            socks_request(stream, control, 1, tcp_port)
            control.sendall(b"\0" * 4)
            if read_exact(stream, 1) != b"R":
                raise RuntimeError("isolated flow was not live before HUP")
            control.settimeout(3)
            server.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"isolated server exited after HUP\n{log.read()[-2000:]}")
                try:
                    if proxy_totals(api_port, secret) == (0, 0):
                        break
                except (OSError, http.client.HTTPException, EOFError):
                    pass
                time.sleep(0.05)
            else:
                raise RuntimeError("isolated HUP did not reset counters before the deadline")
            try:
                control.sendall(b"Q")
                if control.recv(1):
                    raise RuntimeError("old TCP flow still transferred data after HUP")
                outcome = "closed"
            except (BrokenPipeError, ConnectionResetError):
                outcome = "reset"
            except TimeoutError:
                outcome = "no reply within 3s"
    with ExitStack() as stack:
        response = open_rpc(stack, api_port, "SubscribeConnections", secret)
        after_reload = {}
        if not read_connections(response, after_reload) or after_reload:
            raise RuntimeError("expected empty connection state after HUP")
    if proxy_totals(api_port, secret) != (0, 0):
        raise RuntimeError("expected new proxy counters after HUP")
    upload, download = tcp_flow(start_fresh_client(), tcp_port, 19, 31)
    if proxy_totals(api_port, secret) != (upload, download):
        raise RuntimeError("post-HUP flow did not match new counters")
    print(f"OBSERVED isolated HUP: old client socket {outcome}")
    print("PASS isolated HUP reset API counters and allowed a new TCP flow")


def main(stack):
    version = subprocess.check_output([BINARY, "version"], text=True)
    print(version.splitlines()[0], flush=True)
    if "sing-box version 1.14.4\n" not in version:
        raise RuntimeError("this audit expects sing-box 1.14.4")
    directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="hy2-api-audit-")))
    os.umask(0o077)
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext",
        "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(cert),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Hold all port reservations concurrently to avoid assigning the same port twice.
    with ExitStack() as reservations:
        ports = []
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_STREAM):
            sock = reservations.enter_context(socket.socket(socket.AF_INET, kind))
            sock.bind((HOST, 0))
            ports.append(sock.getsockname()[1])
    hy2_port, api_port, proxy_a, proxy_b = ports
    tcp_port = start_target(stack, socketserver.ThreadingTCPServer, TcpTarget)
    udp_port = start_target(stack, socketserver.ThreadingUDPServer, UdpTarget)
    secret = secrets.token_urlsafe(32)
    names = ("hy2-audit-control", "user-91001") if sys.argv[1:] == ["--operator"] else ("audit-a", "audit-b")
    users = [{"name": name, "password": secrets.token_urlsafe(24)} for name in names]

    server_config = {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "hysteria2", "tag": "hy2-audit", "listen": HOST, "listen_port": hy2_port,
            "users": users, "udp_timeout": "2s",
            "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)},
        }],
        "outbounds": [{"type": "direct"}],
        "services": [{
            "type": "api", "tag": "audit-api", "listen": HOST, "listen_port": api_port,
            "secret": secret, "dashboard": False,
        }],
    }
    server, server_log = spawn(stack, directory, "server", server_config)
    wait_listener(server, server_log, api_port)

    if sys.argv[1:] == ["--mihomo"]:
        from hy2_lite.subscriptions import render

        binary = os.environ["HY2_AUDIT_MIHOMO"]
        mihomo_home = directory / "mihomo"
        mihomo_home.mkdir()
        config = mihomo_home / "config.yaml"
        item = dict(name=users[0]["name"], password=users[0]["password"],
                    host=HOST, port=hy2_port, sni="localhost")
        profile = render(item, "yaml")
        config.write_text(profile, encoding="utf-8")
        subprocess.run([binary, "-t", "-d", str(mihomo_home), "-f", str(config)],
                       check=True, capture_output=True, timeout=10)
        config.write_text(f"socks-port: {proxy_a}\nbind-address: {HOST}\nallow-lan: false\n" + profile,
                          encoding="utf-8")
        log = stack.enter_context((mihomo_home / "process.log").open("w+"))
        client = subprocess.Popen([binary, "-d", str(mihomo_home), "-f", str(config)],
                                  env=dict(os.environ, SSL_CERT_FILE=str(cert)),
                                  stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        stack.callback(stop_child, client)
        wait_listener(client, log, proxy_a)
        up, down = tcp_flow(proxy_a, tcp_port, 37, 61)
        actual = proxy_totals(api_port, secret)
        if actual != (up, down):
            raise RuntimeError(f"Mihomo traffic did not traverse Hysteria2: expected {(up, down)}, got {actual}")
        print(f"PASS Mihomo exported YAML and real Hysteria2 traffic upload={up} download={down}")
        return

    if sys.argv[1:] == ["--operator"]:
        from cryptography.fernet import Fernet
        from hy2_lite.database import connect, migrate
        from hy2_lite.operator import execute_next, run_job
        from hy2_lite.original_subscriptions import original_url
        from hy2_lite.subscriptions import lookup

        database = directory / "operator.sqlite3"
        key, token = directory / "subscription.key", directory / "api.key"
        key.write_bytes(Fernet.generate_key())
        token.write_text(secret, encoding="ascii")
        migrate(database)
        settings = dict(binary=BINARY, config=str(directory / "server.json"),
                        state=str(directory / "operator-state"), work_directory=str(directory),
                        endpoint=dict(host=HOST, port=hy2_port, sni="localhost"),
                        inbound="hy2-audit", api_port=api_port, api_token_file=str(token),
                        control_user=names[0], subscription_key_file=str(key), probe_ca_file=str(cert))
        for action in ("add", "disable", "enable", "delete"):
            with connect(database, write=True) as db:
                db.execute(
                    "INSERT INTO config_jobs(id,request_key,action,user_id,display_name,created_at) "
                    "VALUES (?,?,?,'hy2-audit-operator','Operator audit',0)", (action, action, action),
                )
            if run_job(database, settings, action, reload_process=server) != "applied":
                raise RuntimeError(f"operator job failed: {action}")
            item = lookup(database, Fernet(key.read_bytes()), user_id="hy2-audit-operator")
            if bool(item) != (action in {"add", "enable"}):
                raise RuntimeError("operator job left unexpected subscription state")
            print(f"PASS operator {action}: verified real Hysteria2 authentication and subscription state")
        cipher = Fernet(key.read_bytes())
        url = "https://legacy.example/sub/test.yaml"
        with connect(database, write=True) as db:
            db.execute("INSERT INTO users(user_id,display_name,origin,managed_at) VALUES (?,?,'original',0)",
                       (names[1], "Original audit"))
            db.execute("INSERT INTO original_subscriptions VALUES (?,?)", (names[1], cipher.encrypt(url.encode())))
        for action in ("disable", "enable", "delete"):
            job_id = secrets.token_hex(16)
            with connect(database, write=True) as db:
                db.execute("INSERT INTO config_jobs(id,request_key,action,user_id,created_at,execute_now) "
                           "VALUES (?,?,?,?,0,1)",
                           (job_id, job_id, action, names[1]))
            execute_next(database, settings, execute=lambda *args, **kwargs:
                         run_job(*args, reload_process=server, **kwargs))
            with connect(database) as db:
                status = db.execute("SELECT status FROM config_jobs WHERE id=?", (job_id,)).fetchone()[0]
            if status != "applied":
                raise RuntimeError("original operator job failed")
            if original_url(database, cipher, names[1]) != url:
                raise RuntimeError("original subscription URL changed")
            print(f"PASS original {action}: verified real Hysteria2 authentication and preserved subscription URL")
        return

    def start_client(name, user, proxy, client_stack=stack):
        client, client_log = spawn(client_stack, directory, name, {
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": HOST, "listen_port": proxy}],
            "outbounds": [{
                "type": "hysteria2", "server": HOST, "server_port": hy2_port, "password": user["password"],
                "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)},
            }],
        })
        wait_listener(client, client_log, proxy)

    def fresh_port():
        with socket.socket() as reservation:
            reservation.bind((HOST, 0))
            return reservation.getsockname()[1]

    if sys.argv[1:] in (["--auth"], ["--transaction"], ["--jobs"]):
        def probe(user, allowed=True):
            with ExitStack() as client_stack:
                proxy = fresh_port()
                start_client("probe", user, proxy, client_stack)
                try:
                    tcp_flow(proxy, tcp_port, 19, 31)
                except (EOFError, ConnectionResetError, RuntimeError) as error:
                    if allowed or isinstance(error, RuntimeError) and not str(error).startswith("SOCKS request failed: 050"):
                        raise
                    return
                if not allowed:
                    raise RuntimeError(f"unexpected authentication success for {user['name']}")

        if sys.argv[1:] == ["--auth"]:
            auth_test(directory, server_config, server, api_port, secret, users, probe)
            return

        from hy2_lite.collector import NativeAPI
        from hy2_lite.config_transaction import ConfigTransaction, Rejected, digest

        live = directory / "server.json"
        native = NativeAPI(api_port, secret, "hy2-audit")
        added = {"name": "hy2-audit-new", "password": secrets.token_urlsafe(32)}

        def check(path):
            subprocess.run([BINARY, "check", "-D", str(directory), "-c", str(path)],
                           check=True, capture_output=True, timeout=5)

        def reload():
            epoch = native.epoch()
            server.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and server.poll() is None:
                try:
                    if native.epoch() != epoch:
                        return
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                time.sleep(0.05)
            raise RuntimeError("isolated reload failed")

        fail_probe = False
        original = live.read_bytes()

        def verify(expected, previous):
            entries = json.loads(expected)["inbounds"][0]["users"]
            if sys.argv[1:] == ["--jobs"]:
                before = json.loads(previous)["inbounds"][0]["users"]
                target = next(item for item in entries + before if item["name"] == "hy2-audit-job")
                probe(users[0])
                probe(target, allowed=target in entries)
                return
            present = any(item["name"] == added["name"] for item in entries)
            probe(users[0])
            probe(added, allowed=present)
            if fail_probe and present:
                raise RuntimeError("injected readiness failure")

        tx = ConfigTransaction(live, directory / "transactions", "hy2-audit", check, reload, verify)
        if sys.argv[1:] == ["--jobs"]:
            from cryptography.fernet import Fernet
            from hy2_lite.database import connect, migrate
            from hy2_lite.jobs import JobRunner
            from hy2_lite.subscriptions import Endpoint, lookup, render

            db_path = directory / "jobs.sqlite3"
            migrate(db_path)
            cipher = Fernet(Fernet.generate_key())
            runner = JobRunner(db_path, tx, cipher, Endpoint(HOST, hy2_port, "localhost"))
            name = "hy2-audit-job"
            token = None
            for action in ("add", "disable", "enable", "delete"):
                with connect(db_path, write=True) as db:
                    db.execute(
                        "INSERT INTO config_jobs(id, request_key, action, user_id, display_name, created_at) "
                        "VALUES (?, ?, ?, ?, 'Audit job', 0)", (action, action, action, name),
                    )
                if runner.run(action) != "applied":
                    raise RuntimeError(f"job failed: {action}")
                item = lookup(db_path, cipher, user_id=name)
                if action == "add":
                    token = item["token"]
                    export = directory / "export.json"
                    export.write_text(render(item, "json"), encoding="utf-8")
                    check(export)
                if action == "enable" and (not item or item["token"] != token):
                    raise RuntimeError("re-enabled subscription changed its token")
                if action in {"disable", "delete"} and lookup(db_path, cipher, token=token) is not None:
                    raise RuntimeError("revoked subscription remained accessible")
                print(f"PASS {action} job: live config and subscription state verified")
            return
        for action in ("add", "disable", "enable", "delete"):
            password = added["password"] if action in {"add", "enable"} else None
            tx.apply(action, digest(live.read_bytes()), action, added["name"], password)
            print(f"PASS transactional {action}: target and control credentials checked")
        fail_probe = True
        before_failure = live.read_bytes()
        try:
            tx.apply("failed", digest(live.read_bytes()), "add", added["name"], added["password"])
        except Rejected as error:
            if "restored" not in str(error):
                raise
        else:
            raise RuntimeError("injected health failure unexpectedly committed")
        if live.read_bytes() != before_failure or json.loads(live.read_bytes()) != json.loads(original):
            raise RuntimeError("rollback did not restore original users")
        print("PASS transactional rollback: prior config and real authentication restored")
        return

    for user, proxy in zip(users, (proxy_a, proxy_b)):
        start_client(user["name"], user, proxy)

    def start_fresh_client():
        proxy = fresh_port()
        start_client("fresh-client", users[1], proxy)
        return proxy

    with ExitStack() as rejected:
        response = open_rpc(rejected, api_port, "SubscribeConnections")
        status = response.getheader("grpc-status")
        if status != "16":
            raise RuntimeError(f"missing-token request: expected gRPC status 16, got {status}")
        print("PASS missing token rejected")

    records = {}
    with ExitStack() as initial:
        response = open_rpc(initial, api_port, "SubscribeConnections", secret)
        if not read_connections(response, records) or records:
            raise RuntimeError("expected an empty initial snapshot")
        expected = {
            ("audit-a", "tcp"): tcp_flow(proxy_a, tcp_port, 317, 631),
            ("audit-b", "tcp"): tcp_flow(proxy_b, tcp_port, 491, 867),
            ("audit-a", "udp"): udp_flow(proxy_a, udp_port, 109, 163),
            ("audit-b", "udp"): udp_flow(proxy_b, udp_port, 217, 293),
        }
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            observed = {(user, network): (up, down)
                        for user, network, up, down, closed in records.values()
                        if closed}
            if observed == expected:
                break
            read_connections(response, records)
        else:
            raise RuntimeError(f"connection totals differ: expected {expected}, observed {observed}")
        if len(records) != len(expected):
            raise RuntimeError(f"expected four connection IDs, observed {len(records)}")
    for (user, network), (up, down) in sorted(expected.items()):
        print(f"PASS {user} {network.upper()} upload={up} download={down}")

    if sys.argv[1:] == ["--collector"]:
        from hy2_lite.collector import ClosedBuffer, NativeAPI, merge_closed, read_closed
        from hy2_lite.database import connect, migrate
        from hy2_lite.traffic import HOUR, hourly, ingest

        path = directory / "collector.sqlite3"
        migrate(path)
        with connect(path, write=True) as db:
            db.executemany(
                "INSERT INTO users(user_id, display_name, origin, managed_at) VALUES (?, ?, 'managed', 0)",
                [(item["name"], item["name"]) for item in users],
            )
        api = NativeAPI(api_port, secret, "hy2-audit")
        baseline = api.snapshot()
        ingest(path, baseline)
        buffer = ClosedBuffer()
        stop = threading.Event()
        ready = threading.Event()
        stack.callback(stop.set)
        threading.Thread(target=read_closed, args=(api, buffer, stop, ready), daemon=True).start()
        if not ready.wait(5):
            raise RuntimeError("collector did not open its continuous connection stream")
        up, down = tcp_flow(proxy_a, tcp_port, 37, 61)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            closed, _ = buffer.read(baseline.epoch, time.time_ns() // 1_000_000)
            new = [flow for flow in closed if flow.created_at >= baseline.at]
            if new:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("continuous stream did not capture the new short connection")
        sample = api.snapshot()
        # Exercise the event path without relying on the server's closed cache.
        from dataclasses import replace
        sample = merge_closed(replace(sample, connections=()), new)
        ingest(path, sample)
        if ingest(path, sample):
            raise RuntimeError("collector accepted replay of the same observation")
        start = baseline.at // HOUR * HOUR
        end = (sample.at // HOUR + 1) * HOUR
        rows = hourly(path, "user", "audit-a", start, end)
        if tuple(sum(row[direction] or 0 for row in rows) for direction in ("upload", "download")) != (up, down):
            raise RuntimeError(f"collector failed to persist exact user bytes: {rows}")
        print(f"PASS native API event stream to SQLite user hourly upload={up} download={down}")
        if os.environ.get("HY2_AUDIT_SUSTAINED") == "1":
            totals = {"audit-a": [up, down], "audit-b": [0, 0]}
            buffer.acknowledge(sample.epoch, new)
            for batch in range(6):
                due = time.monotonic() + 5
                for index in range(30):
                    slot = index % 2
                    name = users[slot]["name"]
                    sent, received = tcp_flow((proxy_a, proxy_b)[slot], tcp_port, 37, 61)
                    totals[name][0] += sent
                    totals[name][1] += received
                    time.sleep(0.05)
                time.sleep(max(0, due - time.monotonic()))
                sample = api.snapshot()
                flows, gap = buffer.read(sample.epoch, sample.at)
                if gap:
                    raise RuntimeError("unexpected interruption in sustained test")
                sample = merge_closed(replace(sample, connections=()), flows)
                ingest(path, sample)
                buffer.acknowledge(sample.epoch, flows)
                end = (sample.at // HOUR + 1) * HOUR
                for name, expected_totals in totals.items():
                    rows = hourly(path, "user", name, start, end)
                    actual = [sum(row[direction] or 0 for row in rows) for direction in ("upload", "download")]
                    if actual != expected_totals:
                        raise RuntimeError(f"batch {batch + 1} {name}: expected {expected_totals}, got {actual}")
            print(f"PASS sustained stream: 180 short flows over 30s plus baseline probe; {totals}")
        return

    offline = tcp_flow(proxy_b, tcp_port, 73, 97)
    with ExitStack() as resumed:
        response = open_rpc(resumed, api_port, "SubscribeConnections", secret)
        snapshot = {}
        if not read_connections(response, snapshot):
            raise RuntimeError("reconnected stream did not send its initial snapshot")
        deadline = time.monotonic() + 8
        extra = snapshot.keys() - records.keys()
        while not extra and time.monotonic() < deadline:
            read_connections(response, snapshot)
            extra = snapshot.keys() - records.keys()
        if len(extra) != 1:
            raise RuntimeError(f"expected one new connection after reconnect, observed {len(extra)}")
        identity = next(iter(extra))
        deadline = time.monotonic() + 8
        while not snapshot[identity][-1] and time.monotonic() < deadline:
            read_connections(response, snapshot)
        if snapshot[identity] != ("audit-b", "tcp", *offline, True):
            raise RuntimeError(f"disconnected-period TCP accounting mismatch: {snapshot[identity]}")
    print(f"PASS short reconnect recovered audit-b TCP upload={offline[0]} download={offline[1]}")

    expected_total = tuple(sum(pair[i] for pair in (*expected.values(), offline)) for i in (0, 1))
    actual_total = proxy_totals(api_port, secret)
    if actual_total != expected_total:
        raise RuntimeError(f"proxy totals differ: expected {expected_total}, observed {actual_total}")
    print(f"PASS proxy totals upload={actual_total[0]} download={actual_total[1]}")
    if sys.argv[1:] == ["--stress"]:
        stress_test(server, server_log, api_port, secret, (proxy_a, proxy_b), tcp_port,
                    actual_total, start_fresh_client)


if sys.argv[1:] not in ([], ["--stress"], ["--auth"], ["--collector"], ["--transaction"], ["--jobs"], ["--operator"], ["--mihomo"]):
    sys.exit("Usage: bash hy2-lite-api-audit.sh [--stress | --auth | --collector | --transaction | --jobs | --operator | --mihomo]")
with ExitStack() as stack:
    main(stack)
print("RESULT: PASS (isolated listeners and temporary files cleaned up)")
PY
