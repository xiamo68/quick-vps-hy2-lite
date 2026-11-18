"""Maintain a fresh installation created by install.sh."""

import argparse
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory, mkdtemp, mkstemp

from deploy.preflight import read_config


APP = Path("/opt/hy2-lite/current")
BIN = APP.parent / "bin"
ETC = Path("/etc/hy2-lite")
STATE = Path("/var/lib/hy2-lite-install")
JOURNAL = Path("/var/lib/hy2-lite-operator")
DB = Path("/var/lib/hy2-lite/panel.sqlite3")
CONFIG = Path("/etc/sing-box/config.json")
ACME = ETC / "acme"
ACME_STATE = Path("/var/lib/hy2-lite-acme")
EDGE = "hy2-lite-edge.service"
WEB = "hy2-lite-web.service"
CONSUMERS = ("hy2-lite-executor.service", "hy2-lite-collector.service", WEB)
FILES = {
    "panel.sqlite3": DB,
    "sing-box.json": CONFIG,
    "api.token": ETC / "api.token",
    "totp.fernet-key": ETC / "totp.fernet-key",
    "subscriptions.fernet-key": ETC / "subscriptions.fernet-key",
}


def run(*args, timeout=45):
    return subprocess.run(args, check=True, timeout=timeout, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)


def replace(path, content):
    metadata = path.stat()
    fd, temporary = mkstemp(prefix=".hy2-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            if isinstance(content, Path):
                with content.open("rb") as source:
                    shutil.copyfileobj(source, output)
            else:
                output.write(content)
            os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(output.fileno(), metadata.st_mode & 0o777)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def confirm(message, phrase):
    if not sys.stdin.isatty() or input(f"{message}  Type {phrase} to continue: ") != phrase:
        raise ValueError("Operation canceled.")


def health(host):
    run("curl", "-q", "-fsS", "--noproxy", "*", "--retry", "5", "--retry-all-errors",
        "--retry-delay", "1", "--max-time", "5", "--connect-to",
        f"{host}:443:127.0.0.1:443", f"https://{host}/healthz")


def bind_domain(config_path, address, port):
    settings = read_config(config_path)
    domain = settings.panel_host
    if (settings.public_ipv4, settings.proxy_port) != (address, port) or not domain:
        raise ValueError("Keep the installed public IPv4 and port, and set PANEL_HOST.")
    aliases = {"panel_alias": f"https://{domain}", "proxy_alias": settings.proxy_host}
    alias_path = ETC / "aliases.json"
    old_bytes = alias_path.read_bytes()
    existing = json.loads(old_bytes)
    if existing and existing != aliases:
        raise ValueError("A different domain binding already exists. This release supports one set of domains.")
    for name in {domain, settings.proxy_host} - {None}:
        result = subprocess.run(["getent", "ahostsv4", name], capture_output=True, text=True, timeout=5)
        if {line.split()[0] for line in result.stdout.splitlines() if line.strip()} != {address}:
            raise ValueError(f"The A record for {name} must point to the installed public IPv4.")
    confirm(f"This will issue a certificate for {domain} and restart the panel. The IP endpoint will remain available.", "BIND")
    lineage = ACME / "live/hy2-lite-domain/fullchain.pem"
    if not lineage.is_file():
        run(str(BIN / "certbot"), "certonly", "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email", "--config-dir", str(ACME),
            "--work-dir", str(ACME_STATE / "work"), "--logs-dir", str(ACME_STATE / "logs"),
            "--webroot", "--webroot-path", str(ACME_STATE / "webroot"),
            "--cert-name", "hy2-lite-domain", "-d", domain, timeout=180)
    from cryptography import x509
    certificate = x509.load_pem_x509_certificate(lineage.read_bytes())
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if domain not in names.get_values_for_type(x509.DNSName):
        raise ValueError("The staged certificate does not match the requested domain.")
    run(str(BIN / "publish-certificate"), "--prepare", "--domain")
    edge_path = ETC / "edge.Caddyfile"
    old_edge = edge_path.read_bytes()
    template = Path(__file__).with_name("templates") / "edge-https.Caddyfile"
    edge = template.read_text().replace("@PUBLIC_IPV4@", address)
    edge += (f"\nhttps://{domain} {{\n"
             "\ttls /etc/hy2-lite/tls/domain-current/fullchain.pem /etc/hy2-lite/tls/domain-current/privkey.pem\n"
             "\treverse_proxy 127.0.0.1:18770\n}\n")
    with TemporaryDirectory() as folder:
        candidate = Path(folder) / "Caddyfile"
        candidate.write_text(edge)
        run("caddy", "validate", "--config", str(candidate), "--adapter", "caddyfile")
    try:
        replace(alias_path, json.dumps(aliases).encode() + b"\n")
        replace(edge_path, edge.encode())
        run("systemctl", "restart", WEB)
        run("systemctl", "reload", EDGE)
        health(address)
        health(domain)
    except Exception:
        replace(alias_path, old_bytes)
        replace(edge_path, old_edge)
        run("systemctl", "restart", WEB)
        run("systemctl", "reload", EDGE)
        raise ValueError("Domain verification failed. The previous panel configuration was restored.") from None
    print(f"Local HTTPS passed for the domain and IP endpoints: https://{domain}")


@contextmanager
def quiescent_jobs():
    import fcntl

    with (JOURNAL / "jobs.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (JOURNAL / "pending.json").exists():
            raise ValueError("Review the unfinished proxy transaction before proceeding.")
        with closing(sqlite3.connect(f"{DB.as_uri()}?mode=ro", uri=True, timeout=3)) as database:
            if database.execute("SELECT 1 FROM config_jobs WHERE status IN ('pending','running') OR needs_review=1").fetchone():
                raise ValueError("Resolve pending or flagged jobs before proceeding.")
        yield


def snapshot(source, target):
    with (closing(sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)) as original,
          closing(sqlite3.connect(target)) as copy):
        original.backup(copy)
        if copy.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("SQLite integrity check failed.")


def no_unfinished_jobs(path):
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=3)) as database:
        return not database.execute(
            "SELECT 1 FROM config_jobs WHERE status IN ('pending','running') OR needs_review=1"
        ).fetchone()


def backup(output, address, port):
    with quiescent_jobs(), TemporaryDirectory() as folder:
        root = Path(folder)
        snapshot(DB, root / "panel.sqlite3")
        if not no_unfinished_jobs(root / "panel.sqlite3"):
            raise ValueError("Jobs appeared during the snapshot. Retry after they finish.")
        for name, path in FILES.items():
            if path != DB:
                shutil.copyfile(path, root / name)
        (root / "manifest.json").write_text(json.dumps({"version": 1, "ip": address, "port": port}))
        fd, temporary = mkstemp(prefix=".hy2-backup-", dir=output.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                    for name in sorted({*FILES, "manifest.json"}):
                        archive.add(root / name, arcname=name, recursive=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, output)
        finally:
            Path(temporary).unlink(missing_ok=True)
    print("Backup created. It contains credentials. Store it privately.")


def unpack(source, folder):
    names = {*FILES, "manifest.json"}
    seen = set()
    with tarfile.open(source, "r:gz") as archive:
        for member in archive:
            if (member.name not in names or member.name in seen or not member.isfile()
                    or not 0 < member.size <= (512 * 1024**2 if member.name == "panel.sqlite3" else 4 * 1024**2)):
                raise ValueError("The backup has unexpected files or exceeds the size limit.")
            with archive.extractfile(member) as stream, (folder / member.name).open("xb") as output:
                shutil.copyfileobj(stream, output)
            seen.add(member.name)
    if seen != names:
        raise ValueError("The backup is missing required files.")
    return json.loads((folder / "manifest.json").read_bytes())


def checkpoint():
    with closing(sqlite3.connect(DB, timeout=3)) as db:
        if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
            raise ValueError("The database is still in use.")
        if db.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
            raise ValueError("Could not clear the old database WAL.")


def switch_files(folder):
    checkpoint()
    for name, path in FILES.items():
        replace(path, folder / name)
    with closing(sqlite3.connect(DB, timeout=3)) as db:
        if db.execute("PRAGMA journal_mode=WAL").fetchone() != ("wal",):
            raise ValueError("Could not enable WAL for the restored database.")


def verify_proxy():
    helper = Path(__file__).with_name("check_install_probe.py")
    run("systemctl", "reload", "sing-box.service")
    run("/usr/bin/env", f"PYTHONPATH={APP}", sys.executable, "-B", str(helper))


def config_without_accounts(config):
    inbound, = [item for item in config["inbounds"] if item.get("tag") == "hy2-us"]
    api, = [item for item in config["services"] if item.get("tag") == "hy2-lite-api"]
    inbound.pop("users")
    api.pop("secret")
    return config


def restore(source, address, port):
    sys.path.insert(0, str(APP))
    from hy2_lite.restore import restore_snapshot

    with TemporaryDirectory() as folder:
        stage = Path(folder)
        if unpack(source, stage) != {"version": 1, "ip": address, "port": port}:
            raise ValueError("Restore requires the same public IPv4 and UDP port.")
        restore_snapshot(stage / "panel.sqlite3", stage / "validated.sqlite3")
        (stage / "validated.sqlite3").replace(stage / "panel.sqlite3")
        if not no_unfinished_jobs(stage / "panel.sqlite3"):
            raise ValueError("The backup contains unfinished jobs.")
        from cryptography.fernet import Fernet
        for name in ("totp.fernet-key", "subscriptions.fernet-key"):
            Fernet((stage / name).read_bytes().strip())
        config = json.loads((stage / "sing-box.json").read_bytes())
        api, = [item for item in config["services"] if item.get("tag") == "hy2-lite-api"]
        if api["secret"] != (stage / "api.token").read_text().strip():
            raise ValueError("The backup API credentials do not match.")
        if config_without_accounts(config) != config_without_accounts(json.loads(CONFIG.read_bytes())):
            raise ValueError("The base proxy configuration differs from the current installation. Check the installed version.")
        run(str(BIN / "sing-box"), "-c", str(stage / "sing-box.json"), "check")
        confirm("This will replace panel data and proxy accounts. Reloading may interrupt connections.", "RESTORE")
        with quiescent_jobs():
            previous = Path(mkdtemp(prefix="before-restore-", dir=STATE))
            print(f"Pre-restore data saved at {previous}", flush=True)
            resume = True
            try:
                run("systemctl", "stop", *CONSUMERS)
                for name, path in FILES.items():
                    if path == DB:
                        snapshot(path, previous / name)
                    else:
                        shutil.copyfile(path, previous / name)
                try:
                    resume = False
                    switch_files(stage)
                    verify_proxy()
                    run("systemctl", "start", *CONSUMERS)
                    health(address)
                    resume = True
                except Exception:
                    try:
                        run("systemctl", "stop", *CONSUMERS)
                        switch_files(previous)
                        verify_proxy()
                        resume = True
                    except Exception:
                        raise ValueError(f"Rollback verification failed. Check the services and recover from {previous}.") from None
                    raise ValueError("Restore verification failed. The previous data was restored.") from None
            finally:
                if resume:
                    run("systemctl", "start", *CONSUMERS)
    print("Restore complete. Proxy and panel checks passed. Sign in again.")


def main():
    import fcntl

    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    bind = commands.add_parser("bind-domain")
    bind.add_argument("--config", type=Path, default=Path("install.env"))
    for name in ("backup", "restore"):
        commands.add_parser(name).add_argument("archive", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not (STATE / "complete").is_file():
        parser.error("Use sudo on a VPS with a completed installation.")
    try:
        address, port = (STATE / "settings").read_text().split()
        with Path("/run/lock/hy2-lite-install.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == "bind-domain":
                bind_domain(args.config, address, int(port))
            elif args.action == "backup":
                backup(args.archive, address, int(port))
            else:
                restore(args.archive, address, int(port))
    except (OSError, sqlite3.Error, tarfile.TarError, KeyError, ValueError,
            argparse.ArgumentTypeError, subprocess.SubprocessError) as exc:
        if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError):
            parser.exit(1, f"Operation failed: {exc}\n")
        parser.exit(1, "Operation failed. Check the backup, service status, and system logs.\n")


if __name__ == "__main__":
    main()
