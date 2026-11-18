from datetime import datetime, timezone
import csv
from io import BytesIO, StringIO
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from flask import Flask, g, jsonify, redirect, render_template, request, url_for
import pyotp
import segno

from .auth import (
    IDLE_SECONDS, LIMIT_SECONDS, MAX_FAILURES, PASSWORDS, SESSION_SECONDS,
    consume_otp, password_matches, session_digest, validate_password,
)
from .database import audit, connect
from .system_metrics import latest_system
from .subscriptions import lookup, render
from .original_subscriptions import is_original_id, original_url
from .user_ids import allocate_user_id
from .traffic import daily, hourly, lifetime


COOKIE = "__Host-hy2-session"
PREFIX = "/api/v1"
STATES = {"enabled", "disabled", "deleted"}
MUTATIONS = {"POST", "PATCH", "PUT", "DELETE"}
NAVIGATION = (
    ("dashboard", "Dashboard", "⌂"), ("users", "Users", "♙"), ("traffic", "Traffic", "▥"),
    ("subscriptions", "Subscriptions", "▤"), ("settings", "Settings", "⚙"),
)


def error(code, status):
    return jsonify(code=code), status


def utc_millis(value):
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec="milliseconds")


def user_data(row):
    item = dict(row)
    for field in ("managed_at", "deleted_at", "last_active_at"):
        item[field] = utc_millis(item[field])
    return item


def pagination():
    try:
        page = int(request.args.get("page", "1"))
        if 1 <= page <= 100_000:
            return (page - 1) * 50
    except ValueError:
        pass
    return None


def create_app(database, public_origin, totp_key, subscription_key=None, backup_directory=None,
               immediate_jobs=False, *, panel_alias=None, proxy_alias=None):
    origins = {}
    for origin in (public_origin, panel_alias):
        if origin is None:
            continue
        url = urlsplit(origin)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or origin != f"https://{url.netloc}" or not url.netloc.isascii()):
            raise ValueError("An exact HTTPS origin is required.")
        origins[url.netloc] = origin
    cipher = Fernet(totp_key)
    subscription_cipher = Fernet(subscription_key) if subscription_key else None
    database = Path(database)
    backup_directory = Path(backup_directory).resolve(strict=True) if backup_directory else None
    if backup_directory and not backup_directory.is_dir():
        raise ValueError("Backup directory must already exist.")
    if not database.is_file():
        raise ValueError("Initialize the database first.")
    with connect(database) as db:
        if not db.execute("SELECT 1 FROM admin").fetchone():
            raise ValueError("Initialize the administrator first.")
    dummy_hash = PASSWORDS.hash(secrets.token_urlsafe(32))
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=16 * 1024, TRUSTED_HOSTS=list(origins))

    @app.after_request
    def headers(response):
        response.headers.update({
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        return response

    @app.errorhandler(413)
    def too_large(_):
        return error("request_too_large", 413)

    @app.before_request
    def authenticate():
        if request.method in MUTATIONS and (request.host not in origins
                or request.headers.get("Origin") != origins[request.host]):
            return error("invalid_origin", 403)
        if request.endpoint in {"login", "login_page", "favicon", "static", "public_subscription", "health"} or request.endpoint is None:
            return None
        def unauthenticated():
            if request.endpoint == "panel":
                return redirect(url_for("login_page"))
            return error("unauthenticated", 401)

        token = request.cookies.get(COOKIE, "")
        if len(token) != 43:
            return unauthenticated()
        g.digest = session_digest(token)
        g.now = int(time.time())
        with connect(database, write=True) as db:
            session = db.execute("SELECT * FROM sessions WHERE digest = ?", (g.digest,)).fetchone()
            if session is None:
                return unauthenticated()
            if g.now - session["created_at"] >= SESSION_SECONDS or g.now - session["seen_at"] >= IDLE_SECONDS:
                db.execute("DELETE FROM sessions WHERE digest = ?", (g.digest,))
                return unauthenticated()
            db.execute("UPDATE sessions SET seen_at = ? WHERE digest = ?", (g.now, g.digest))
            g.actor = db.execute("SELECT username FROM admin WHERE id = 1").fetchone()[0]
        return None

    @app.get("/login")
    def login_page():
        return render_template("panel.html", page="login", title="Administrator sign-in")

    @app.get("/favicon.ico")
    def favicon():
        return "", 204

    @app.get("/healthz")
    def health():
        try:
            with connect(database) as db:
                initialized = db.execute("SELECT 1 FROM admin WHERE id=1").fetchone()
        except sqlite3.Error:
            initialized = None
        return (jsonify(status="ok"), 200) if initialized else (jsonify(status="unavailable"), 503)

    @app.get("/")
    @app.get("/users")
    @app.get("/traffic")
    @app.get("/subscriptions")
    @app.get("/settings")
    def panel():
        page = request.path.strip("/") or "dashboard"
        title = next(label for key, label, _ in NAVIGATION if key == page)
        return render_template("panel.html", page=page, title=title, navigation=NAVIGATION,
                               immediate_jobs=immediate_jobs)

    def payload():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def active_admin(db):
        return db.execute(
            "SELECT admin.* FROM admin WHERE id = 1 AND EXISTS (SELECT 1 FROM sessions WHERE digest = ?)",
            (g.digest,),
        ).fetchone()

    def verified(db, admin, data):
        return password_matches(admin["password_hash"], data.get("password")) and (
            not admin["totp"] or consume_otp(db, admin, admin["totp"], data.get("otp"), g.now, cipher)
        )

    @app.post(PREFIX + "/session")
    def login():
        data = payload()
        now = int(time.time())
        token = secrets.token_urlsafe(32)
        with connect(database, write=True) as db:
            limit = db.execute("SELECT * FROM login_limits WHERE scope = 'admin'").fetchone()
            start = now
            failures = 0
            if limit and 0 <= now - limit["started_at"] < LIMIT_SECONDS:
                start, failures = limit["started_at"], limit["failures"]
            if failures >= MAX_FAILURES:
                response, status = error("login_rate_limited", 429)
                response.headers["Retry-After"] = str(LIMIT_SECONDS - (now - start))
                return response, status
            admin = db.execute("SELECT * FROM admin WHERE id = 1").fetchone()
            known = data.get("username") == admin["username"]
            valid = password_matches(admin["password_hash"] if known else dummy_hash, data.get("password"))
            if not known or not valid or (
                admin["totp"] and not consume_otp(db, admin, admin["totp"], data.get("otp"), now, cipher)
            ):
                db.execute(
                    "INSERT INTO login_limits VALUES ('admin', ?, ?) "
                    "ON CONFLICT(scope) DO UPDATE SET started_at=excluded.started_at, failures=excluded.failures",
                    (start, failures + 1),
                )
                audit(db, now, "anonymous", "session.login", result="denied")
                return error("invalid_credentials", 401)
            db.execute("DELETE FROM login_limits WHERE scope = 'admin'")
            db.execute("DELETE FROM sessions WHERE created_at <= ? OR seen_at <= ?",
                       (now - SESSION_SECONDS, now - IDLE_SECONDS))
            old_token = request.cookies.get(COOKIE, "")
            if len(old_token) == 43:
                db.execute("DELETE FROM sessions WHERE digest = ?", (session_digest(old_token),))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (session_digest(token), now, now))
            audit(db, now, admin["username"], "session.login")
        response = jsonify(username=admin["username"])
        response.set_cookie(COOKIE, token, secure=True, httponly=True, samesite="Lax", path="/",
                            max_age=SESSION_SECONDS)
        return response

    @app.delete(PREFIX + "/session")
    def logout():
        with connect(database, write=True) as db:
            db.execute("DELETE FROM sessions WHERE digest = ?", (g.digest,))
            audit(db, g.now, g.actor, "session.logout")
        response = app.response_class(status=204)
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="Lax", path="/")
        return response

    @app.get(PREFIX + "/users")
    def users():
        offset = pagination()
        query = request.args.get("q", "").strip()
        state = request.args.get("state", "")
        sort = request.args.get("sort", "name")
        ordering = {"name": "display_name COLLATE NOCASE, user_id", "id": "user_id",
                    "newest": "managed_at DESC, user_id"}
        if offset is None or len(query) > 100 or (state and state not in STATES) or sort not in ordering:
            return error("invalid_query", 400)
        with connect(database) as db:
            rows = db.execute(
                "SELECT * FROM users WHERE effective_state <> 'deleted' AND (? = '' OR effective_state = ?) "
                "AND (instr(lower(display_name), lower(?)) > 0 OR instr(lower(user_id), lower(?)) > 0) "
                f"ORDER BY {ordering[sort]} LIMIT 51 OFFSET ?", (state, state, query, query, offset),
            ).fetchall()
        return jsonify(items=[user_data(row) for row in rows[:50]], has_more=len(rows) > 50)

    @app.post(PREFIX + "/users")
    @app.post(PREFIX + "/users/<user_id>/state")
    @app.delete(PREFIX + "/users/<user_id>")
    def queue_user_change(user_id=None):
        data = payload()
        key = request.headers.get("Idempotency-Key", "")
        version = data.get("expected_version")
        execute_now = data.pop("execute_now", False)
        if not isinstance(execute_now, bool) or (execute_now and not immediate_jobs):
            return error("immediate_execution_unavailable", 409)
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", key) or (
            version is not None and (not isinstance(version, str) or not re.fullmatch(r"[a-f0-9]{64}", version))
        ):
            return error("invalid_job_request", 400)
        display = remark = None
        if user_id is None:
            if data.keys() - {"display_name", "remark", "expected_version"}:
                return error("invalid_job_request", 400)
            display, remark = data.get("display_name"), data.get("remark", "")
            if (not isinstance(display, str) or not 1 <= len(display.strip()) <= 80
                    or not isinstance(remark, str) or len(remark) > 500 or "\x00" in display + remark):
                return error("invalid_user_metadata", 400)
            display = display.strip()
            action = "add"
        elif request.method == "DELETE":
            if data.keys() - {"confirm_user_id", "expected_version"} or data.get("confirm_user_id") != user_id:
                return error("confirmation_required", 400)
            action = "delete"
        else:
            if data.keys() - {"enabled", "confirm_user_id", "expected_version"} or (
                not isinstance(data.get("enabled"), bool) or data.get("confirm_user_id") != user_id
            ):
                return error("confirmation_required", 400)
            action = "enable" if data["enabled"] else "disable"
        with connect(database, write=True) as db:
            if not active_admin(db):
                return error("unauthenticated", 401)
            prior = db.execute("SELECT * FROM config_jobs WHERE request_key=?", (key,)).fetchone()
            if prior:
                if (prior["action"], prior["display_name"], prior["remark"], prior["expected_version"]) != (
                    action, display, remark, version
                ) or prior["execute_now"] != execute_now or (user_id is not None and user_id != prior["user_id"]):
                    return error("idempotency_conflict", 409)
                return jsonify(id=prior["id"], user_id=prior["user_id"], status=prior["status"]), 202
            if user_id is None:
                user_id = allocate_user_id(db, display)
            else:
                row = db.execute("SELECT origin, effective_state FROM users WHERE user_id=?", (user_id,)).fetchone()
                if row is None:
                    return error("user_not_found", 404)
                if row["origin"] != "managed" and not is_original_id(user_id):
                    return error("original_user_protected", 403)
                state = row["effective_state"]
                if state == "deleted" or (action == "enable" and state == "enabled") or (
                    action == "disable" and state == "disabled"
                ):
                    return error("invalid_state_transition", 409)
                if execute_now:
                    replaced = db.execute(
                        "UPDATE config_jobs SET status='failed' WHERE user_id=? AND status='pending' AND execute_now=0",
                        (user_id,),
                    )
                    if replaced.rowcount:
                        audit(db, g.now, g.actor, "user.legacy_request_replaced", user_id)
                if db.execute("SELECT 1 FROM config_jobs WHERE user_id=? AND status IN ('pending','running')",
                              (user_id,)).fetchone():
                    return error("job_already_pending", 409)
            job = secrets.token_hex(16)
            db.execute(
                "INSERT INTO config_jobs(id, request_key, action, user_id, display_name, remark, "
                "expected_version, created_at, execute_now) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (job, key, action, user_id, display, remark, version, g.now * 1000, execute_now),
            )
            audit(db, g.now, g.actor, "user.change_requested", user_id)
        return jsonify(id=job, user_id=user_id, status="pending"), 202

    @app.get(PREFIX + "/jobs/<job_id>")
    def config_job(job_id):
        with connect(database) as db:
            row = db.execute("SELECT id, action, user_id, status, created_at, execute_now, needs_review "
                             "FROM config_jobs WHERE id=?",
                             (job_id,)).fetchone()
        if row is None:
            return error("job_not_found", 404)
        return jsonify(dict(row) | {"created_at": utc_millis(row["created_at"])})

    @app.get(PREFIX + "/subscriptions")
    def subscriptions():
        offset = pagination()
        if offset is None:
            return error("invalid_query", 400)
        with connect(database) as db:
            rows = db.execute(
                """SELECT u.user_id, u.display_name, u.origin, u.effective_state,
                          s.user_id IS NOT NULL AS managed_subscription,
                          o.user_id IS NOT NULL AS original_subscription
                   FROM users u LEFT JOIN managed_subscriptions s USING(user_id)
                   LEFT JOIN original_subscriptions o USING(user_id)
                   WHERE u.effective_state <> 'deleted'
                   ORDER BY u.display_name, u.user_id LIMIT 51 OFFSET ?""", (offset,),
            ).fetchall()
        return jsonify(items=[dict(row) for row in rows[:50]], has_more=len(rows) > 50)

    @app.post(PREFIX + "/subscriptions/<user_id>/export")
    def export_subscription(user_id):
        kind = payload().get("format")
        if kind not in ("url", "yaml", "json", "uri", "qr"):
            return error("unsupported_subscription_format", 400)
        if subscription_cipher is None:
            return error("subscription_key_unavailable", 503)
        item = lookup(database, subscription_cipher, user_id=user_id)
        if kind in {"url", "qr"}:
            url = (origins[request.host] + "/s/" + item["token"]) if item else original_url(database, subscription_cipher, user_id)
            if url and kind == "url":
                return jsonify(url=url)
            if url:
                output = BytesIO()
                segno.make(url, micro=False).save(output, kind="png", scale=5)
                return app.response_class(output.getvalue(), mimetype="image/png")
        if item is None:
            return error("subscription_not_available", 404)
        if proxy_alias and origins[request.host] == panel_alias:
            item = dict(item, host=proxy_alias)
        if kind == "uri":
            return jsonify(uri=render(item, kind))
        return app.response_class(
            render(item, kind), mimetype="application/json" if kind == "json" else "application/yaml",
            headers={"Content-Disposition": f'attachment; filename="hy2-subscription.{kind}"'},
        )

    @app.get("/s/<token>")
    def public_subscription(token):
        item = lookup(database, subscription_cipher, token=token) if subscription_cipher else None
        if item is None:
            return error("subscription_not_available", 404)
        if proxy_alias and origins[request.host] == panel_alias:
            item = dict(item, host=proxy_alias)
        # Some subscription clients preserve escaped quotes and use the full
        # filename as the profile title. A bare ASCII token avoids both.
        return app.response_class(render(item, "yaml"), mimetype="application/yaml",
                                  headers={"Content-Disposition": "attachment; filename=hy2-lite"})

    @app.patch(PREFIX + "/users/<user_id>")
    def edit_user(user_id):
        data = payload()
        if not data or data.keys() - {"display_name", "remark"}:
            return error("invalid_user_metadata", 400)
        for key, value in data.items():
            if (not isinstance(value, str) or len(value) > {"display_name": 80, "remark": 500}[key]
                    or "\x00" in value or (key == "display_name" and not value.strip())):
                return error("invalid_user_metadata", 400)
        with connect(database, write=True) as db:
            if not active_admin(db):
                return error("unauthenticated", 401)
            row = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if row is None:
                return error("user_not_found", 404)
            db.execute("UPDATE users SET display_name = ?, remark = ? WHERE user_id = ?",
                       (data.get("display_name", row["display_name"]).strip(),
                        data.get("remark", row["remark"]), user_id))
            audit(db, g.now, g.actor, "user.update", user_id)
            updated = db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return jsonify(user_data(updated))

    @app.get(PREFIX + "/system/audit")
    def audit_log():
        offset = pagination()
        if offset is None:
            return error("invalid_query", 400)
        with connect(database) as db:
            rows = db.execute("SELECT * FROM admin_audit_logs ORDER BY at DESC, id DESC LIMIT 51 OFFSET ?",
                              (offset,)).fetchall()
        return jsonify(items=[dict(row) | {"at": utc_millis(row["at"])} for row in rows[:50]],
                       has_more=len(rows) > 50)

    @app.get(PREFIX + "/traffic")
    @app.get(PREFIX + "/traffic.csv")
    def traffic():
        scope = request.args.get("scope", "user")
        subject = request.args.get("interface" if scope == "network" else "user_id", "")
        if scope not in {"proxy", "user", "network"} or (scope != "proxy") != bool(subject):
            return error("invalid_scope", 400)
        granularity = request.args.get("granularity", "hour")
        if granularity not in {"hour", "day"}:
            return error("invalid_granularity", 400)
        try:
            limits = [datetime.fromisoformat(request.args[key].replace("Z", "+00:00"))
                      for key in ("from", "to")]
            if any(value.utcoffset() is None or value.second or value.microsecond for value in limits):
                return error("invalid_range", 400)
            start, end = [int(value.timestamp() * 1000) for value in limits]
            query = daily if granularity == "day" else hourly
            rows = query(database, scope, subject, start, end)
        except (KeyError, ValueError, OverflowError):
            return error("invalid_range", 400)
        if scope == "user":
            with connect(database) as db:
                user = db.execute("SELECT last_active_at FROM users WHERE user_id = ?", (subject,)).fetchone()
            if user is None:
                return error("user_not_found", 404)
        if granularity == "hour":
            for row in rows:
                row["hour"] = utc_millis(row["hour"])
        if request.path.endswith(".csv"):
            data = StringIO()
            period = "day" if granularity == "day" else "hour"
            writer = csv.DictWriter(data, fieldnames=[period, "upload", "download", "coverage"])
            writer.writeheader()
            writer.writerows(rows)
            return app.response_class(
                data.getvalue(), mimetype="text/csv",
                headers={"Content-Disposition": 'attachment; filename="traffic.csv"'},
            )
        return jsonify(items=rows, last_active_at=utc_millis(user[0]) if scope == "user" else None,
                       lifetime=lifetime(database, scope, subject))

    @app.get(PREFIX + "/system/collector")
    @app.get(PREFIX + "/dashboard")
    def system():
        data = latest_system(database)
        if data["system"]:
            data["system"]["at"] = utc_millis(data["system"]["at"])
        collector = data["collector"]
        collector["last_success_at"] = utc_millis(collector["last_success_at"])
        if collector["latest_event"]:
            event = collector["latest_event"]
            event["start"], event["end"] = utc_millis(event["start"]), utc_millis(event["end"])
        return jsonify(data)

    @app.post(PREFIX + "/system/password")
    def password():
        data = payload()
        try:
            validate_password(data.get("new_password"))
        except ValueError:
            return error("invalid_new_password", 400)
        with connect(database, write=True) as db:
            admin = active_admin(db)
            if admin is None:
                return error("unauthenticated", 401)
            if not verified(db, admin, data):
                return error("invalid_credentials", 401)
            db.execute("UPDATE admin SET password_hash = ?, pending_totp = NULL, pending_until = NULL WHERE id = 1",
                       (PASSWORDS.hash(data["new_password"]),))
            db.execute("DELETE FROM sessions WHERE digest <> ?", (g.digest,))
            audit(db, g.now, g.actor, "admin.password")
        return "", 204

    @app.get(PREFIX + "/system/security")
    def security_status():
        with connect(database) as db:
            admin = active_admin(db)
            if admin is None:
                return error("unauthenticated", 401)
        return jsonify(totp_enabled=bool(admin["totp"]))

    @app.get(PREFIX + "/system/backups")
    @app.post(PREFIX + "/system/backups")
    def backups():
        if not backup_directory:
            return error("backup_directory_unavailable", 503) if request.method == "POST" else jsonify(enabled=False, last_at=None)
        if request.method == "POST":
            with connect(database) as check:
                if not active_admin(check):
                    return error("unauthenticated", 401)
            with tempfile.NamedTemporaryFile(dir=backup_directory, prefix=".backup-", delete=False) as file:
                pending = Path(file.name)
            try:
                with connect(database) as source, connect(pending) as target:
                    source.backup(target)
                    if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise sqlite3.DatabaseError("Backup integrity check failed")
                pending.replace(backup_directory / f"hy2-lite-{g.now}-{secrets.token_hex(4)}.sqlite3")
            except (OSError, sqlite3.Error):
                return error("backup_failed", 503)
            finally:
                pending.unlink(missing_ok=True)
            with connect(database, write=True) as db:
                audit(db, g.now, g.actor, "database.backup")
        existing = [path.stat().st_mtime_ns // 1_000_000 for path in backup_directory.glob("hy2-lite-*.sqlite3")
                    if path.is_file() and not path.is_symlink()]
        return jsonify(enabled=True, last_at=utc_millis(max(existing)) if existing else None)

    @app.post(PREFIX + "/system/totp/setup")
    def setup_totp():
        with connect(database, write=True) as db:
            admin = active_admin(db)
            if admin is None:
                return error("unauthenticated", 401)
            if admin["totp"]:
                return error("totp_already_enabled", 409)
            if not verified(db, admin, payload()):
                return error("invalid_credentials", 401)
            secret = pyotp.random_base32()
            db.execute("UPDATE admin SET pending_totp = ?, pending_until = ? WHERE id = 1",
                       (cipher.encrypt(secret.encode()).decode(), g.now + 300))
            audit(db, g.now, g.actor, "admin.totp.setup")
        uri = pyotp.TOTP(secret).provisioning_uri(name=g.actor, issuer_name="HY2 Lite")
        return jsonify(secret=secret, uri=uri)

    @app.post(PREFIX + "/system/totp/confirm")
    def confirm_totp():
        with connect(database, write=True) as db:
            admin = active_admin(db)
            if admin is None:
                return error("unauthenticated", 401)
            if not admin["pending_totp"] or admin["pending_until"] <= g.now:
                return error("totp_setup_required", 409)
            if not consume_otp(db, admin, admin["pending_totp"], payload().get("otp"), g.now, cipher):
                return error("invalid_otp", 401)
            db.execute("UPDATE admin SET totp = pending_totp, pending_totp = NULL, pending_until = NULL WHERE id = 1")
            db.execute("DELETE FROM sessions WHERE digest <> ?", (g.digest,))
            audit(db, g.now, g.actor, "admin.totp.enable")
        return "", 204

    @app.post(PREFIX + "/system/totp/disable")
    def disable_totp():
        with connect(database, write=True) as db:
            admin = active_admin(db)
            if admin is None:
                return error("unauthenticated", 401)
            if not admin["totp"]:
                return error("totp_not_enabled", 409)
            if not verified(db, admin, payload()):
                return error("invalid_credentials", 401)
            db.execute("UPDATE admin SET totp = NULL, last_totp_step = NULL WHERE id = 1")
            db.execute("DELETE FROM sessions WHERE digest <> ?", (g.digest,))
            audit(db, g.now, g.actor, "admin.totp.disable")
        return "", 204

    return app
