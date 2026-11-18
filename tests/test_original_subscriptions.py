import json
from pathlib import Path
import tempfile
import unittest

from cryptography.fernet import Fernet

from hy2_lite.__main__ import import_original_users
from hy2_lite.database import connect, migrate

from hy2_lite.original_subscriptions import match_original, original_url, save_original_urls
from hy2_lite.subscriptions import Endpoint


class OriginalSubscriptionsTests(unittest.TestCase):
    def test_matches_only_unique_password_and_endpoint(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            users = [{"name": f"user-{i}", "password": f"secret-{i}"} for i in range(91001, 91012)]
            config = json.dumps({"inbounds": [{"tag": "hy2-us", "type": "hysteria2", "users": users}]})
            for user in users:
                path = root / (user["name"] + ".yaml")
                path.write_text("proxies:\n  - type: hysteria2\n    server: proxy.example\n"
                                "    port: 24443\n    sni: proxy.example\n"
                                f"    password: {user['password']}\n", encoding="utf-8")
            endpoint = Endpoint("proxy.example", 24443, "proxy.example")
            result = match_original(config, root, "hy2-us", endpoint)
            self.assertEqual(len(result), 11)
            self.assertEqual(result["user-91001"], "user-91001.yaml")
            db = root / "panel.sqlite3"
            migrate(db)
            import_original_users(db, list(result))
            cipher = Fernet(Fernet.generate_key())
            base = "https://legacy.example/sub/"
            save_original_urls(db, cipher, result, base)
            self.assertEqual(original_url(db, cipher, "user-91001"), base + "user-91001.yaml")
            with connect(db) as connection:
                blob = connection.execute("SELECT url FROM original_subscriptions").fetchone()[0]
            self.assertNotIn(b"legacy.example", blob)
            path = root / "user-91001.yaml"
            path.write_text(path.read_text().replace("proxy.example", "wrong.example"))
            with self.assertRaisesRegex(ValueError, "10/11"):
                match_original(config, root, "hy2-us", endpoint)
