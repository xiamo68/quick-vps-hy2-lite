"""Restore a panel snapshot to a new database path."""
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import os

from .database import connect, migrate


def restore_snapshot(source, destination):
    source = Path(source).resolve(strict=True)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Restore destination already exists")
    with TemporaryDirectory(prefix=".hy2-restore-", dir=destination.parent) as folder:
        candidate = Path(folder) / "restored.sqlite3"
        fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as snapshot:
                if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Snapshot integrity check failed")
                version = snapshot.execute("PRAGMA user_version").fetchone()[0]
                if version == 0 or not snapshot.execute("SELECT 1 FROM admin WHERE id=1").fetchone():
                    raise ValueError("Snapshot is not an initialized HY2 Lite database")
                with connect(candidate) as db:
                    snapshot.backup(db)
            migrate(candidate)
            with connect(candidate, write=True) as db:
                if db.execute("PRAGMA foreign_key_check").fetchone():
                    raise ValueError("Snapshot contains invalid references")
                db.execute("DELETE FROM sessions")
                db.execute("DELETE FROM login_limits")
                db.execute("UPDATE admin SET pending_totp=NULL, pending_until=NULL")
            with connect(candidate) as db:
                db.execute("PRAGMA journal_mode=DELETE")
        except sqlite3.DatabaseError:
            raise ValueError("Invalid HY2 Lite snapshot") from None
        os.link(candidate, destination)
