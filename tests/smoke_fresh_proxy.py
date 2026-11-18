"""Exercise the rendered proxy with a temporary IP certificate and loopback ports."""

import json
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from install_config import documents
from hy2_lite.collector import NativeAPI
from hy2_lite.operator import free_port, probe, probe_target
from hy2_lite.subscriptions import Endpoint


def main(binary):
    address, token, password = "127.0.0.1", "local-test-token", "local-test-password"
    with TemporaryDirectory() as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key),
                        "-out", str(cert)], check=True, capture_output=True)
        with socket.socket(type=socket.SOCK_DGRAM) as reservation:
            reservation.bind((address, 0))
            proxy_port = reservation.getsockname()[1]
        config, settings = documents(address, proxy_port, token, password)
        api_port = free_port()
        config["services"][0]["listen_port"] = api_port
        inbound = config["inbounds"][0]
        inbound["listen"] = address
        inbound["tls"].update(certificate_path=str(cert), key_path=str(key))
        config_path = root / "config.json"
        with probe_target(host=settings["probe_host"]) as (port, body):
            config["route"]["rules"][0]["port"] = [port]
            config_path.write_text(json.dumps(config))
            command = [binary, "-D", directory, "-c", str(config_path)]
            subprocess.run([*command, "check"], check=True)
            with subprocess.Popen([*command, "run"]) as server:
                try:
                    api = NativeAPI(api_port, token)
                    for _ in range(40):
                        try:
                            api.epoch()
                            break
                        except OSError:
                            if server.poll() is not None:
                                raise RuntimeError("isolated sing-box failed to start")
                            time.sleep(0.1)
                    else:
                        raise RuntimeError("loopback API did not start")
                    endpoint = Endpoint(address, proxy_port, address)
                    assert probe(binary, endpoint, password, port, body, cert,
                                 target_host=settings["probe_host"])
                    with probe_target(host=settings["probe_host"]) as (blocked_port, blocked_body):
                        assert not probe(binary, endpoint, password, blocked_port, blocked_body, cert,
                                         target_host=settings["probe_host"])
                    print("PASS rendered config, IP TLS, native API, authentication and loopback routing")
                finally:
                    server.terminate()
                    server.wait(timeout=5)


if __name__ == "__main__":
    main(sys.argv[1])
