import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from hy2_lite.app import create_app
from hy2_lite.__main__ import import_original_users
from hy2_lite.auth import create_admin
from hy2_lite.database import connect, migrate
from hy2_lite.traffic import Connection, Snapshot, ingest


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "test.sqlite3"
        migrate(self.db)
        create_admin(self.db, "admin", "correct horse battery staple")
        self.app = create_app(self.db, "https://panel.example", Fernet.generate_key())
        self.client = self.app.test_client()
        self.base = "https://panel.example"

    def request(self, method, path, data=None):
        return self.client.open(path, method=method, json=data, base_url=self.base,
                                headers={"Origin": self.base})

    def login(self, **extra):
        return self.request("POST", "/api/v1/session", {
            "username": "admin", "password": "correct horse battery staple", **extra,
        })

    def test_migration_idempotence_and_single_admin(self):
        migrate(self.db)
        with self.assertRaises(ValueError):
            create_admin(self.db, "another", "another strong password")
        with connect(self.db) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 8)
            stored = db.execute("SELECT password_hash FROM admin").fetchone()[0]
            self.assertTrue(stored.startswith("$argon2id$"))

    def test_queue_is_idempotent_without_creating_active_user(self):
        self.login()
        arguments = dict(method="POST", path="/api/v1/users", base_url=self.base,
                         headers={"Origin": self.base, "Idempotency-Key": "local-test-job-001"})
        result = self.client.open(**arguments, json={"display_name": "New"})
        self.assertEqual(result.status_code, 202)
        self.assertEqual(self.client.open(**arguments, json={"display_name": "New"}).json, result.json)
        self.assertEqual(self.client.open(**arguments, json={"display_name": "Other"}).status_code, 409)
        self.assertEqual(self.request("GET", "/api/v1/users").json["items"], [])
        job = self.request("GET", "/api/v1/jobs/" + result.json["id"])
        self.assertEqual(job.json["status"], "pending")

    def test_original_import_is_idempotent_and_preserves_metadata(self):
        ids = [f"user-{port}" for port in range(91001, 91012)]
        self.assertEqual(import_original_users(self.db, ids), 11)
        self.login()
        self.request("PATCH", "/api/v1/users/user-91001", {"display_name": "我的电脑"})
        self.assertEqual(import_original_users(self.db, ids), 0)
        with self.assertRaises(ValueError):
            import_original_users(self.db, ids[:-1] + [ids[0]])
        self.assertEqual(self.request("GET", "/api/v1/users?q=电脑").json["items"][0]["origin"], "original")

    def test_traffic_json_and_csv_distinguish_missing_from_observed(self):
        ids = [f"user-{port}" for port in range(91001, 91012)]
        import_original_users(self.db, ids)
        ingest(self.db, Snapshot(1, 0, 0, 0))
        ingest(self.db, Snapshot(1, 5000, 41, 61, (Connection("one", ids[0], 100, 41, 61),)))
        query = "?user_id=user-91001&from=1970-01-01T00:00:00Z&to=1970-01-01T02:00:00Z"
        self.assertEqual(self.request("GET", "/api/v1/traffic" + query).status_code, 401)
        self.login()
        rows = self.request("GET", "/api/v1/traffic" + query).json["items"]
        self.assertEqual([(row["upload"], row["coverage"]) for row in rows],
                         [(41, "partial"), (None, "missing")])
        csv = self.request("GET", "/api/v1/traffic.csv" + query).get_data(as_text=True)
        self.assertIn(",41,61,partial", csv)
        self.assertIn(",,,missing", csv)

    def test_login_requires_origin_and_logout_revokes(self):
        self.assertEqual(self.request("GET", "/api/v1/users").status_code, 401)
        self.assertEqual(self.client.post("/api/v1/session", json={}, base_url=self.base).status_code, 403)
        response = self.login()
        self.assertEqual(response.status_code, 200)
        for flag in ("Secure", "HttpOnly", "SameSite=Lax"):
            self.assertIn(flag, response.headers["Set-Cookie"])
        self.assertEqual(self.request("GET", "/api/v1/users").status_code, 200)
        self.assertEqual(self.request("DELETE", "/api/v1/session").status_code, 204)
        self.assertEqual(self.request("GET", "/api/v1/users").status_code, 401)

    def test_edit_metadata_and_log_without_credentials(self):
        with connect(self.db) as db:
            db.execute("INSERT INTO users(user_id, display_name, origin, managed_at) VALUES (?, ?, ?, ?)",
                       ("user-91001", "user-91001", "original", 100))
        self.login()
        path = "/api/v1/users/user-91001"
        response = self.request("PATCH", path, {"display_name": "我的电脑", "remark": "书房"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["user_id"], "user-91001")
        self.assertEqual(self.request("GET", "/api/v1/users?q=电脑").json["items"][0]["remark"], "书房")
        self.assertEqual(self.request("PATCH", path, {"password": "ignored"}).status_code, 400)
        logs = self.request("GET", "/api/v1/system/audit").json["items"]
        self.assertIn("user.update", [entry["action"] for entry in logs])
        self.assertNotIn("correct horse", str(logs))

    def test_rate_limit_and_expiry(self):
        for _ in range(5):
            self.assertEqual(self.request("POST", "/api/v1/session",
                                          {"username": "admin", "password": "bad"}).status_code, 401)
        self.assertEqual(self.login().status_code, 429)
        with patch("hy2_lite.app.time.time", return_value=4_000_000_000):
            self.assertEqual(self.login().status_code, 200)
        with patch("hy2_lite.app.time.time", return_value=4_000_002_000):
            self.assertEqual(self.request("GET", "/api/v1/users").status_code, 401)

    def test_totp_setup_login_replay_and_disable(self):
        import pyotp

        path = "/api/v1/system/totp"
        password = "correct horse battery staple"
        with patch("hy2_lite.app.time.time", return_value=4_000_000_000):
            self.assertEqual(self.login().status_code, 200)
            setup = self.request("POST", path + "/setup", {"password": password})
        self.assertEqual(setup.status_code, 200)
        self.assertIn("no-store", setup.headers["Cache-Control"])
        totp = pyotp.TOTP(setup.json["secret"])
        with connect(self.db) as db:
            self.assertNotIn(setup.json["secret"], db.execute("SELECT pending_totp FROM admin").fetchone()[0])
        with patch("hy2_lite.app.time.time", return_value=4_000_000_000):
            self.assertEqual(self.request("POST", path + "/confirm", {"otp": totp.at(4_000_000_000)}).status_code, 204)
            self.request("DELETE", "/api/v1/session")
            self.assertEqual(self.login(otp=totp.at(4_000_000_000)).status_code, 401)
        with patch("hy2_lite.app.time.time", return_value=4_000_000_030):
            self.assertEqual(self.login().status_code, 401)
            self.assertEqual(self.login(otp=totp.at(4_000_000_030)).status_code, 200)
        with patch("hy2_lite.app.time.time", return_value=4_000_000_060):
            response = self.request("POST", path + "/disable",
                                    {"password": password, "otp": totp.at(4_000_000_060)})
            self.assertEqual(response.status_code, 204)

    def test_password_change_revokes_other_sessions(self):
        self.login()
        other = self.app.test_client()
        response = other.post("/api/v1/session", base_url=self.base, headers={"Origin": self.base},
                              json={"username": "admin", "password": "correct horse battery staple"})
        self.assertEqual(response.status_code, 200)
        rejected = self.request("POST", "/api/v1/system/password", {
            "password": "correct horse battery staple", "new_password": "test123",
        })
        self.assertEqual(rejected.status_code, 400)
        response = self.request("POST", "/api/v1/system/password", {
            "password": "correct horse battery staple", "new_password": "test1234",
        })
        self.assertEqual(response.status_code, 204)
        self.assertEqual(other.get("/api/v1/users", base_url=self.base).status_code, 401)
        self.assertEqual(self.request("GET", "/api/v1/users").status_code, 200)
        self.assertEqual(self.login().status_code, 401)
        self.assertEqual(self.login(password="test1234").status_code, 200)
