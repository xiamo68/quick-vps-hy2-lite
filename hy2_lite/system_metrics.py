import json
from pathlib import Path
import shutil
import subprocess
import time

from .database import connect
from .traffic import MAX_GAP, record


def counter_rate(old, new, elapsed):
    if elapsed <= 0 or new < old:
        return None
    return (new - old) * 1000 / elapsed


def service_states():
    proxy, caddy, edge = "sing-box.service", "caddy.service", "hy2-lite-edge.service"
    try:
        output = subprocess.run(
            ["systemctl", "show", "--property=Id,LoadState,ActiveState", proxy, caddy, edge],
            capture_output=True, text=True, timeout=4,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    states = {}
    for unit in output.strip().split("\n\n"):
        fields = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
        if fields.get("LoadState") == "not-found":
            continue
        if "Id" in fields and "ActiveState" in fields:
            states[fields["Id"]] = fields["ActiveState"]
    if edge in states:
        # Keep the dashboard's Caddy status key for both installation layouts.
        states[caddy] = states.pop(edge)
    return states


def linux_sample(interface, proc=Path("/proc"), sys=Path("/sys"), disk_path="/"):
    if not interface or interface in {".", "..", "lo"} or Path(interface).name != interface:
        raise ValueError("Expected one non-loopback Linux interface name")
    cpu = [int(value) for value in (proc / "stat").read_text().splitlines()[0].split()[1:9]]
    memory = {}
    for line in (proc / "meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            memory[key] = int(value.split()[0]) * 1024
    disk = shutil.disk_usage(disk_path)
    stats = sys / "class/net" / interface / "statistics"
    boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
    index = (stats.parent / "ifindex").read_text().strip()
    return dict(
        at=time.time_ns() // 1_000_000, boot=boot, interface=interface, interface_index=index,
        cpu_total=sum(cpu), cpu_idle=cpu[3] + cpu[4],
        rx=int((stats / "rx_bytes").read_text()), tx=int((stats / "tx_bytes").read_text()),
        uptime_seconds=int(float((proc / "uptime").read_text().split()[0])),
        memory=dict(total=memory["MemTotal"], available=memory["MemAvailable"],
                    used=memory["MemTotal"] - memory["MemAvailable"]),
        swap=dict(total=memory["SwapTotal"], used=memory["SwapTotal"] - memory["SwapFree"]),
        disk=dict(total=disk.total, used=disk.used, free=disk.free),
        services=service_states(),
    )


def save_sample(path, sample):
    result = dict(sample, cpu_percent=None, rx_bytes_per_second=None, tx_bytes_per_second=None)
    with connect(path, write=True) as db:
        latest = db.execute("SELECT data FROM system_samples ORDER BY at DESC LIMIT 1").fetchone()
        old = json.loads(latest[0]) if latest else None
        if old and sample["at"] <= old["at"]:
            return old
        if old and old["boot"] == sample["boot"]:
            elapsed = sample["at"] - old["at"]
            total = sample["cpu_total"] - old["cpu_total"]
            idle = sample["cpu_idle"] - old["cpu_idle"]
            if total > 0 and 0 <= idle <= total:
                result["cpu_percent"] = round(100 * (total - idle) / total, 2)
            if (old["interface"], old.get("interface_index")) == (sample["interface"], sample.get("interface_index")):
                for direction in ("rx", "tx"):
                    result[direction + "_bytes_per_second"] = counter_rate(
                        old[direction], sample[direction], elapsed
                    )
                rx, tx = result["rx_bytes_per_second"], result["tx_bytes_per_second"]
                if rx is not None and tx is not None:
                    record(db, "network", sample["interface"], old["at"], sample["at"],
                           sample["tx"] - old["tx"], sample["rx"] - old["rx"],
                           observed=True, partial=elapsed > 4 * MAX_GAP)
        db.execute("INSERT INTO system_samples VALUES (?, ?)", (sample["at"], json.dumps(result)))
    return result


def latest_system(path):
    with connect(path) as db:
        latest = db.execute("SELECT data FROM system_samples ORDER BY at DESC LIMIT 1").fetchone()
        collector = db.execute("SELECT at FROM collector_state").fetchone()
        event = db.execute("SELECT start, end, reason FROM collector_events ORDER BY id DESC LIMIT 1").fetchone()
    now = time.time_ns() // 1_000_000
    sample = json.loads(latest[0]) if latest else None
    if sample:
        sample = {key: value for key, value in sample.items()
                  if key not in {"boot", "cpu_idle", "cpu_total", "interface_index"}}
        sample["stale"] = not 0 <= now - sample["at"] <= 120_000
    return dict(system=sample,
                collector=dict(last_success_at=collector[0] if collector else None,
                               status=("unknown" if collector is None else
                                       "observed" if 0 <= now - collector[0] <= MAX_GAP else "stale"),
                               latest_event=dict(event) if event else None))
