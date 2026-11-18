from contextlib import contextmanager
from pathlib import Path
import sqlite3


SCHEMA = (
    """CREATE TABLE admin (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        totp TEXT, pending_totp TEXT, pending_until INTEGER, last_totp_step INTEGER
    )""",
    """CREATE TABLE sessions (
        digest TEXT PRIMARY KEY, created_at INTEGER NOT NULL, seen_at INTEGER NOT NULL
    )""",
    """CREATE TABLE login_limits (
        scope TEXT PRIMARY KEY, started_at INTEGER NOT NULL, failures INTEGER NOT NULL
    )""",
    """CREATE TABLE users (
        user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, remark TEXT NOT NULL DEFAULT '',
        origin TEXT NOT NULL CHECK (origin IN ('original', 'managed')),
        effective_state TEXT NOT NULL DEFAULT 'enabled'
            CHECK (effective_state IN ('enabled', 'disabled', 'deleted')),
        managed_at INTEGER NOT NULL, deleted_at INTEGER
    )""",
    """CREATE TABLE admin_audit_logs (
        id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, target TEXT, result TEXT NOT NULL
    )""",
    "CREATE INDEX audit_by_time ON admin_audit_logs (at DESC, id DESC)",
    "CREATE INDEX users_by_state ON users (effective_state, display_name, user_id)",
)

TRAFFIC_SCHEMA = (
    "ALTER TABLE users ADD COLUMN last_active_at INTEGER",
    """CREATE TABLE collector_state (
        id INTEGER PRIMARY KEY CHECK (id=1), epoch INTEGER NOT NULL, at INTEGER NOT NULL,
        upload INTEGER NOT NULL, download INTEGER NOT NULL, baseline INTEGER NOT NULL
    )""",
    """CREATE TABLE collector_events (
        id INTEGER PRIMARY KEY, start INTEGER NOT NULL, end INTEGER NOT NULL, reason TEXT NOT NULL
    )""",
    """CREATE TABLE connection_offsets (
        epoch INTEGER NOT NULL, id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(user_id),
        at INTEGER NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL, closed INTEGER NOT NULL,
        PRIMARY KEY(epoch, id)
    )""",
    """CREATE TABLE traffic_hourly (
        scope TEXT NOT NULL, subject TEXT NOT NULL, hour INTEGER NOT NULL, upload INTEGER NOT NULL,
        download INTEGER NOT NULL, covered INTEGER NOT NULL, partial INTEGER NOT NULL,
        PRIMARY KEY(scope, subject, hour)
    )""",
)


SYSTEM_SCHEMA = (
    "CREATE TABLE system_samples (at INTEGER PRIMARY KEY, data TEXT NOT NULL)",
    """CREATE TABLE traffic_daily (
        scope TEXT NOT NULL, subject TEXT NOT NULL, day INTEGER NOT NULL,
        upload INTEGER NOT NULL, download INTEGER NOT NULL, covered INTEGER NOT NULL,
        partial INTEGER NOT NULL, PRIMARY KEY(scope, subject, day)
    )""",
    """CREATE TABLE traffic_lifetime (
        scope TEXT NOT NULL, subject TEXT NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL,
        PRIMARY KEY(scope, subject)
    )""",
    "CREATE INDEX traffic_hourly_age ON traffic_hourly(hour)",
    "CREATE INDEX traffic_daily_age ON traffic_daily(day)",
    "CREATE TABLE maintenance_state (id INTEGER PRIMARY KEY CHECK (id=1), cutoff INTEGER NOT NULL)",
)

JOBS_SCHEMA = (
    """CREATE TABLE config_jobs (
        id TEXT PRIMARY KEY, request_key TEXT NOT NULL UNIQUE, action TEXT NOT NULL,
        user_id TEXT NOT NULL, display_name TEXT, remark TEXT, expected_version TEXT,
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','applied','failed')),
        created_at INTEGER NOT NULL
    )""",
    """CREATE UNIQUE INDEX config_jobs_active_target ON config_jobs(user_id)
       WHERE status IN ('pending', 'running')""",
)


SUBSCRIPTIONS_SCHEMA = (
    "ALTER TABLE config_jobs ADD COLUMN apply_version TEXT",
    "ALTER TABLE config_jobs ADD COLUMN staged_payload BLOB",
    """CREATE TABLE managed_subscriptions (
        user_id TEXT PRIMARY KEY REFERENCES users(user_id),
        token_hash TEXT NOT NULL UNIQUE, payload BLOB NOT NULL
    )""",
)

ORIGINAL_SUBSCRIPTIONS_SCHEMA = (
    """CREATE TABLE original_subscriptions (
        user_id TEXT PRIMARY KEY REFERENCES users(user_id), url BLOB NOT NULL
    )""",
)


@contextmanager
def connect(path, *, write=False):
    db = sqlite3.connect(Path(path), timeout=5)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys = ON")
        if write:
            db.execute("BEGIN IMMEDIATE")
        with db:
            yield db
    finally:
        db.close()


def migrate(path):
    with connect(path) as db:
        db.execute("PRAGMA journal_mode = WAL")
    with connect(path, write=True) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            for statement in SCHEMA:
                db.execute(statement)
        if version in (0, 1):
            for statement in TRAFFIC_SCHEMA:
                db.execute(statement)
        if version in (0, 1, 2):
            for statement in SYSTEM_SCHEMA:
                db.execute(statement)
        if version in (0, 1, 2, 3):
            for statement in JOBS_SCHEMA:
                db.execute(statement)
        if version in (0, 1, 2, 3, 4):
            for statement in SUBSCRIPTIONS_SCHEMA:
                db.execute(statement)
        if version in (0, 1, 2, 3, 4, 5):
            for statement in ORIGINAL_SUBSCRIPTIONS_SCHEMA:
                db.execute(statement)
        if 0 <= version <= 6:
            db.execute("""CREATE TABLE disabled_original_credentials (
                user_id TEXT PRIMARY KEY REFERENCES users(user_id), payload BLOB NOT NULL
            )""")
            db.execute("PRAGMA user_version = 7")
        elif version not in (7, 8):
            raise RuntimeError(f"Unsupported database schema version: {version}")
        if 0 <= version <= 7:
            db.execute("ALTER TABLE config_jobs ADD COLUMN execute_now INTEGER NOT NULL DEFAULT 0")
            db.execute("ALTER TABLE config_jobs ADD COLUMN needs_review INTEGER NOT NULL DEFAULT 0")
            db.execute("PRAGMA user_version = 8")


def audit(db, now, actor, action, target=None, result="ok"):
    db.execute(
        "INSERT INTO admin_audit_logs(at, actor, action, target, result) VALUES (?, ?, ?, ?, ?)",
        (now * 1000, actor, action, target, result),
    )
