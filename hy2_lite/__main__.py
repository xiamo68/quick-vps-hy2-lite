import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import time

from cryptography.fernet import Fernet

from .app import create_app
from .auth import create_admin
from .database import audit, connect, migrate
from .config_transaction import RecoveryRequired


def import_original_users(path, ids):
    from .original_subscriptions import is_original_id

    expected = set(ids)
    if len(ids) != 11 or len(expected) != 11 or not all(map(is_original_id, ids)):
        raise ValueError("Supply each of the 11 original user IDs exactly once.")
    now = int(time.time())
    with connect(path, write=True) as db:
        existing = {row["user_id"]: row["origin"] for row in db.execute("SELECT user_id, origin FROM users")}
        if any(user_id not in expected for user_id, origin in existing.items() if origin == "original"):
            raise ValueError("The requested IDs differ from existing original users.")
        if any(existing.get(user_id, "original") != "original" for user_id in ids):
            raise ValueError("An original ID conflicts with an existing managed user.")
        added = sorted(expected - existing.keys())
        db.executemany(
            "INSERT INTO users(user_id, display_name, origin, managed_at) VALUES (?, ?, 'original', ?)",
            [(user_id, user_id, now * 1000) for user_id in added],
        )
        if added:
            audit(db, now, "local-operator", "users.import_original")
    return len(added)


def main():
    parser = argparse.ArgumentParser(description="HY2 Lite local administration")
    parser.add_argument("--db", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate")
    restore = commands.add_parser("restore-db")
    restore.add_argument("snapshot", type=Path)
    admin = commands.add_parser("init-admin")
    admin.add_argument("username")
    original = commands.add_parser("import-original-users")
    original.add_argument("user_ids", nargs=11)
    key = commands.add_parser("generate-totp-key")
    key.add_argument("path", type=Path)
    serve = commands.add_parser("serve")
    serve.add_argument("--origin", required=True)
    serve.add_argument("--totp-key-file", type=Path, required=True)
    serve.add_argument("--subscription-key-file", type=Path)
    serve.add_argument("--backup-directory", type=Path)
    serve.add_argument("--immediate-jobs", action="store_true")
    serve.add_argument("--aliases-file", type=Path)
    worker = commands.add_parser("execute-jobs")
    worker.add_argument("--settings", type=Path, required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--port", type=int, default=18771)
    collect.add_argument("--token-file", type=Path, required=True)
    collect.add_argument("--inbound", default="hy2-us")
    collect.add_argument("--interface", help="Linux network interface for host metrics, e.g. eth0")
    collect.add_argument("--once", action="store_true")
    apply_job = commands.add_parser("apply-job")
    apply_job.add_argument("job_id")
    apply_job.add_argument("--settings", type=Path, required=True)
    apply_job.add_argument("--confirm-original", metavar="ACTION:USER_ID")
    reconcile = commands.add_parser("check-original-subscriptions")
    reconcile.add_argument("--config", type=Path, required=True)
    reconcile.add_argument("--directory", type=Path, required=True)
    reconcile.add_argument("--host", required=True)
    reconcile.add_argument("--port", type=int, default=24443)
    reconcile.add_argument("--sni", required=True)
    reconcile.add_argument("--inbound", default="hy2-us")
    reconcile.add_argument("--record-url-prefix")
    reconcile.add_argument("--subscription-key-file", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "generate-totp-key":
            with args.path.open("xb") as output:
                output.write(Fernet.generate_key() + b"\n")
            return
        if args.command == "migrate":
            migrate(args.db)
            return
        if args.command == "restore-db":
            from .restore import restore_snapshot

            restore_snapshot(args.snapshot, args.db)
            print("Database restored to new path; previous sessions revoked")
            return
        if args.command == "init-admin":
            password = getpass("Administrator password: ")
            if password != getpass("Confirm password: "):
                raise ValueError("Passwords do not match.")
            migrate(args.db)
            create_admin(args.db, args.username, password)
            return
        if args.command == "import-original-users":
            if not args.db.is_file():
                raise ValueError("Initialize the database first.")
            print(f"Original users added: {import_original_users(args.db, args.user_ids)}")
            return
        if args.command == "collect":
            from .collector import NativeAPI, run_collector

            if not args.db.is_file():
                raise ValueError("Initialize the database first.")
            api = NativeAPI(args.port, args.token_file.read_text(encoding="ascii").strip(), args.inbound)
            run_collector(args.db, api, args.once, args.interface)
            return
        if args.command == "apply-job":
            from .operator import read_settings, run_job

            status = run_job(args.db, read_settings(args.settings), args.job_id,
                             confirm_original=args.confirm_original)
            print(f"Job status: {status}")
            if status != "applied":
                raise SystemExit(1)
            return
        if args.command == "check-original-subscriptions":
            from .original_subscriptions import match_original, save_original_urls
            from .subscriptions import Endpoint

            matches = match_original(args.config.read_bytes(), args.directory, args.inbound,
                                     Endpoint(args.host, args.port, args.sni))
            if args.record_url_prefix:
                if not args.subscription_key_file or not args.db.is_file():
                    raise ValueError("Recording URLs requires an initialized database and subscription key")
                cipher = Fernet(args.subscription_key_file.read_bytes().strip())
                save_original_urls(args.db, cipher, matches, args.record_url_prefix)
            print(f"Matched {len(matches)}/11 original subscriptions uniquely")
            return
        if args.command == "execute-jobs":
            from .operator import execute_next, read_settings

            settings = read_settings(args.settings)
            while True:
                execute_next(args.db, settings)
                time.sleep(1)
        from waitress import serve as run

        subscription_key = args.subscription_key_file.read_bytes().strip() if args.subscription_key_file else None
        aliases = json.loads(args.aliases_file.read_bytes()) if args.aliases_file else {}
        app = create_app(args.db, args.origin, args.totp_key_file.read_bytes().strip(),
                         subscription_key, args.backup_directory, immediate_jobs=args.immediate_jobs, **aliases)
        run(app, host="127.0.0.1", port=18770, threads=2,
            max_request_body_size=16 * 1024, expose_tracebacks=False)
    except (OSError, ValueError, RecoveryRequired) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
