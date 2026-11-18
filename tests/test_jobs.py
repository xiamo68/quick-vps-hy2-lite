from pathlib import Path
import tempfile
import unittest

from cryptography.fernet import Fernet
from werkzeug.http import parse_options_header

from hy2_lite.app import create_app
from hy2_lite.auth import create_admin
from hy2_lite.database import connect, migrate
from hy2_lite.config_transaction import ConfigTransaction, encoded
from hy2_lite.jobs import JobRunner
from hy2_lite.operator import execute_next
from hy2_lite.subscriptions import Endpoint, lookup


class JobTests(unittest.TestCase):
    def test_named_ids_handle_unicode_collisions_and_preserve_identity_on_rename(self):
        origin = "https://panel.example"
        create_admin(self.db, "admin", "correct horse battery staple")
        client = create_app(self.db, origin, Fernet.generate_key(), self.key).test_client()
        headers = {"Origin": origin}
        self.assertEqual(client.post("/api/v1/session", base_url=origin, headers=headers, json={
            "username": "admin", "password": "correct horse battery staple",
        }).status_code, 200)

        def submit(key):
            response = client.post("/api/v1/users", base_url=origin, json={"display_name": "测试 1"},
                                   headers={**headers, "Idempotency-Key": key})
            self.assertEqual(response.status_code, 202)
            return response.json

        first = submit("named-account-first")
        self.assertEqual(first["user_id"], "h2-测试-1")
        self.assertEqual(submit("named-account-first"), first)
        self.assertEqual(submit("named-account-second")["user_id"], "h2-测试-1-2")
        self.assertEqual(self.runner.run(first["id"]), "applied")
        self.assertIn(first["user_id"], self.live.read_text(encoding="utf-8"))
        changed = client.patch("/api/v1/users/" + first["user_id"], base_url=origin,
                               headers=headers, json={"display_name": "Renamed"})
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(changed.json["user_id"], first["user_id"])
        self.assertEqual(client.get("/users", base_url=origin).status_code, 200)

    def test_web_confirmation_replaces_legacy_request_and_dispatches_only_confirmed_job(self):
        self.job("add")
        with connect(self.db, write=True) as db:
            for job_id, user in (("old", "hy2-test"), ("unrelated", "user-91001")):
                db.execute("INSERT INTO config_jobs(id,request_key,action,user_id,created_at) "
                           "VALUES (?,?,'delete',?,0)", (job_id, job_id, user))
        origin = "https://panel.example"
        create_admin(self.db, "admin", "correct horse battery staple")
        client = create_app(self.db, origin, Fernet.generate_key(), self.key, immediate_jobs=True).test_client()
        headers = {"Origin": origin, "Idempotency-Key": "confirm-disable-123"}
        self.assertEqual(client.post("/api/v1/session", base_url=origin, headers=headers, json={
            "username": "admin", "password": "correct horse battery staple",
        }).status_code, 200)
        response = client.post("/api/v1/users/hy2-test/state", base_url=origin, headers=headers, json={
            "enabled": False, "confirm_user_id": "hy2-test", "execute_now": True,
        })
        self.assertEqual(response.status_code, 202)
        settings = {"state": str(self.tx.state)}
        def execute(database, settings, job_id, *, confirm_original):
            self.assertEqual(confirm_original, "disable:hy2-test")
            return self.runner.run(job_id)
        self.assertTrue(execute_next(self.db, settings, execute=execute))
        self.assertFalse(execute_next(self.db, settings, execute=execute))
        with connect(self.db) as db:
            states = dict(db.execute("SELECT id,status FROM config_jobs").fetchall())
        self.assertEqual((states["old"], states["unrelated"], states[response.json["id"]]),
                         ("failed", "pending", "applied"))

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        self.db = root / "test.sqlite3"
        migrate(self.db)
        self.live = root / "config.json"
        self.live.write_bytes(encoded({"inbounds": [{"tag": "audit", "type": "hysteria2", "users": []}]}))
        self.reloads = []
        self.tx = ConfigTransaction(self.live, root / "state", "audit", lambda _: None,
                                    lambda: self.reloads.append(True), self.verify)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.runner = JobRunner(self.db, self.tx, self.cipher, Endpoint("proxy.example", 24443, "proxy.example"))
        self.fail = False

    def verify(self, expected, previous):
        if self.fail and b"hy2-test" in expected:
            raise RuntimeError("injected")

    def job(self, action, user_id="hy2-test"):
        with connect(self.db, write=True) as db:
            db.execute(
                "INSERT INTO config_jobs(id, request_key, action, user_id, display_name, created_at) "
                "VALUES (?, ?, ?, ?, 'Test', 0)", (action, action, action, user_id),
            )
        return self.runner.run(action)

    def test_original_lifecycle_keeps_url_and_restores_exact_password(self):
        user_id = "user-91001"
        account = {"name": user_id, "password": "Legacy/password+with symbols"}
        before = encoded({"inbounds": [{"tag": "audit", "type": "hysteria2", "users": [account]}]})
        self.live.write_bytes(before)
        url = self.cipher.encrypt(b"https://legacy.example/test.yaml")
        with connect(self.db, write=True) as db:
            db.execute("INSERT INTO users(user_id,display_name,origin,managed_at) VALUES (?,?,'original',0)",
                       (user_id, "Original"))
            db.execute("INSERT INTO original_subscriptions VALUES (?,?)", (user_id, url))
        verify = self.tx.verify
        def reject_removal(expected, previous):
            if b"user-91001" not in expected:
                raise RuntimeError("injected")
        self.tx.verify = reject_removal
        self.assertEqual(self.job("disable", user_id), "failed")
        self.assertEqual(self.live.read_bytes(), before)
        with connect(self.db, write=True) as db:
            self.assertEqual(db.execute("SELECT effective_state FROM users").fetchone()[0], "enabled")
            self.assertIsNone(db.execute("SELECT payload FROM disabled_original_credentials").fetchone())
            db.execute("DELETE FROM config_jobs WHERE id='disable'")
        # A retry uses a new transaction journal ID.
        self.tx.verify = verify
        with connect(self.db, write=True) as db:
            db.execute("INSERT INTO config_jobs(id,request_key,action,user_id,created_at) "
                       "VALUES ('retry','retry','disable',?,0)", (user_id,))
        self.assertEqual(self.runner.run("retry"), "applied")
        self.assertNotIn(user_id.encode(), self.live.read_bytes())
        self.assertEqual(self.job("enable", user_id), "applied")
        self.assertEqual(self.live.read_bytes(), before)
        self.assertEqual(self.job("delete", user_id), "applied")
        with connect(self.db) as db:
            self.assertEqual(db.execute("SELECT effective_state FROM users").fetchone()[0], "deleted")
            self.assertEqual(db.execute("SELECT url FROM original_subscriptions").fetchone()[0], url)
            self.assertIsNone(db.execute("SELECT payload FROM disabled_original_credentials").fetchone())

    def test_lifecycle_and_stable_url(self):
        self.assertEqual(self.job("add"), "applied")
        item = lookup(self.db, self.cipher, user_id="hy2-test")
        self.assertEqual(item["host"], "proxy.example")
        self.assertEqual(self.runner.run("add"), "applied")
        self.assertEqual(len(self.reloads), 1)
        self.assertEqual(self.job("disable"), "applied")
        self.assertIsNone(lookup(self.db, self.cipher, token=item["token"]))
        self.assertEqual(self.job("enable"), "applied")
        self.assertEqual(lookup(self.db, self.cipher, token=item["token"]), item)
        self.assertEqual(self.job("delete"), "applied")
        self.assertIsNone(lookup(self.db, self.cipher, token=item["token"]))

    def test_failed_apply_does_not_publish(self):
        self.fail = True
        before = self.live.read_bytes()
        self.assertEqual(self.job("add"), "failed")
        self.assertEqual(self.live.read_bytes(), before)
        self.assertIsNone(lookup(self.db, self.cipher, user_id="hy2-test"))

    def test_resume_after_configuration_applied_and_before_publication(self):
        finish = self.runner.finish
        self.runner.finish = lambda *args: self.fail_after_apply()
        with self.assertRaises(InterruptedError):
            self.job("add")
        self.assertIsNone(lookup(self.db, self.cipher, user_id="hy2-test"))
        self.runner.finish = finish
        self.assertEqual(self.runner.run("add"), "applied")
        self.assertEqual(len(self.reloads), 1)
        self.assertIsNotNone(lookup(self.db, self.cipher, user_id="hy2-test"))

    @staticmethod
    def fail_after_apply():
        raise InterruptedError("simulated process interruption")

    def test_delete_disabled_without_second_reload(self):
        self.job("add")
        self.job("disable")
        self.assertEqual(self.job("delete"), "applied")
        self.assertEqual(len(self.reloads), 2)

    def test_http_public_token_and_authenticated_exports(self):
        self.job("add")
        item = lookup(self.db, self.cipher, user_id="hy2-test")
        create_admin(self.db, "admin", "correct horse battery staple")
        origin = "https://panel.example"
        app = create_app(self.db, origin, Fernet.generate_key(), self.key)
        client = app.test_client()
        public = "/s/" + item["token"]
        export = "/api/v1/subscriptions/hy2-test/export"
        result = client.get(public, base_url=origin)
        self.assertEqual(result.status_code, 200)
        self.assertIn("no-store", result.headers["Cache-Control"])
        self.assertIn("type: \"hysteria2\"", result.get_data(as_text=True))

        def post(path, data):
            return client.post(path, base_url=origin, headers={"Origin": origin}, json=data)

        self.assertEqual(post(export, {"format": "url"}).status_code, 401)
        self.assertEqual(post("/api/v1/session", {
            "username": "admin", "password": "correct horse battery staple",
        }).status_code, 200)
        renamed = client.patch("/api/v1/users/hy2-test", base_url=origin,
                               headers={"Origin": origin}, json={"display_name": "测试 1"})
        self.assertEqual(renamed.status_code, 200)
        named = client.get(public, base_url=origin)
        self.assertEqual(named.headers["Content-Disposition"], "attachment; filename=hy2-lite")
        self.assertEqual(parse_options_header(named.headers["Content-Disposition"])[1]["filename"], "hy2-lite")
        self.assertEqual(named.data, result.data)
        self.assertEqual(post(export, {"format": "url"}).json["url"], origin + public)
        self.assertEqual(post(export, {"format": "json"}).json["outbounds"][0]["password"], item["password"])
        self.assertTrue(post(export, {"format": "uri"}).json["uri"].startswith("hysteria2://"))
        self.job("disable")
        self.assertEqual(client.get(public, base_url=origin).status_code, 404)
        self.job("enable")
        self.assertEqual(client.get(public, base_url=origin).status_code, 200)
        self.job("delete")
        self.assertEqual(client.get(public, base_url=origin).status_code, 404)
        for query in ("", "?state=deleted", "?q=hy2-test"):
            self.assertEqual(client.get("/api/v1/users" + query, base_url=origin).json["items"], [])
        with connect(self.db) as db:
            self.assertEqual(db.execute("SELECT effective_state FROM users").fetchone()[0], "deleted")

    def test_domain_keeps_original_subscription_and_rejects_cross_origin_mutations(self):
        self.job("add")
        item = lookup(self.db, self.cipher, user_id="hy2-test")
        create_admin(self.db, "admin", "correct horse battery staple")
        ip, domain = "https://192.0.2.10", "https://panel.example"
        app = create_app(self.db, ip, Fernet.generate_key(), self.key,
                         panel_alias=domain, proxy_alias="node.example")
        client = app.test_client()
        public = "/s/" + item["token"]
        original = client.get(public, base_url=ip).get_data(as_text=True)
        aliased = client.get(public, base_url=domain).get_data(as_text=True)
        self.assertIn('server: "proxy.example"', original)
        self.assertIn('server: "node.example"', aliased)
        self.assertIn('sni: "proxy.example"', aliased)
        credentials = {"username": "admin", "password": "correct horse battery staple"}
        self.assertEqual(client.post("/api/v1/session", base_url=domain,
                                     headers={"Origin": ip}, json=credentials).status_code, 403)
        self.assertEqual(client.post("/api/v1/session", base_url=domain,
                                     headers={"Origin": domain}, json=credentials).status_code, 200)
