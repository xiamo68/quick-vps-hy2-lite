from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.fernet import Fernet

from hy2_lite.app import create_app
from hy2_lite.auth import create_admin
from hy2_lite.database import migrate, connect
from hy2_lite.restore import restore_snapshot


class RestoreTests(unittest.TestCase):
    def test_online_snapshot_restores_login_and_metadata_without_old_sessions(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.sqlite3"
            restored = root / "restored.sqlite3"
            backups = root / "backups"
            backups.mkdir()
            migrate(source)
            create_admin(source, "admin", "test restore passphrase")
            with connect(source, write=True) as db:
                db.execute("INSERT INTO users(user_id,display_name,origin,managed_at) VALUES ('id','测试','original',0)")
            origin = "https://panel.example"
            key = Fernet.generate_key()
            auth = dict(base_url=origin, headers={"Origin": origin})
            credentials = {"username": "admin", "password": "test restore passphrase"}
            client = create_app(source, origin, key, backup_directory=backups).test_client()
            self.assertEqual(client.post("/api/v1/session", json=credentials, **auth).status_code, 200)
            self.assertEqual(client.post("/api/v1/system/backups", json={}, **auth).status_code, 200)
            snapshot, = backups.glob("*.sqlite3")
            restore_snapshot(snapshot, restored)
            with self.assertRaises(FileExistsError):
                restore_snapshot(snapshot, restored)
            new_client = create_app(restored, origin, key).test_client()
            cookie = client.get_cookie("__Host-hy2-session", domain="panel.example")
            new_client.set_cookie(cookie.key, cookie.value, domain="panel.example")
            self.assertEqual(new_client.get("/api/v1/users", **auth).status_code, 401)
            self.assertEqual(new_client.post("/api/v1/session", json=credentials, **auth).status_code, 200)
            self.assertEqual(new_client.get("/api/v1/users", **auth).json["items"][0]["display_name"], "测试")

    def test_invalid_snapshot_does_not_create_destination(self):
        with TemporaryDirectory() as temp:
            source = Path(temp) / "invalid.sqlite3"
            destination = Path(temp) / "destination.sqlite3"
            source.write_bytes(b"not a database")
            with self.assertRaises(ValueError):
                restore_snapshot(source, destination)
            self.assertFalse(destination.exists())
