"""Check the new proxy over loopback with its dedicated control account."""

import json
from pathlib import Path
import time

from hy2_lite.operator import probe, probe_target, read_settings
from hy2_lite.subscriptions import Endpoint


def main():
    settings = read_settings(Path("/etc/hy2-lite/operator.json"))
    config = json.loads(Path(settings["config"]).read_bytes())
    inbound, = [item for item in config["inbounds"] if item["tag"] == settings["inbound"]]
    account, = [item for item in inbound["users"] if item["name"] == settings["control_user"]]
    endpoint = Endpoint("127.0.0.1", settings["endpoint"]["port"], settings["endpoint"]["sni"])
    with probe_target(settings["probe_port"], settings["probe_host"]) as (port, body):
        for _ in range(3):
            if probe(settings["binary"], endpoint, account["password"], port, body,
                     target_host=settings["probe_host"]):
                print("PASS: Local proxy authentication")
                return
            time.sleep(1)
    raise ValueError("authentication check failed")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Local proxy authentication failed. Check sing-box and its certificate.") from None
