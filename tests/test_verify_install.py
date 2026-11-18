from contextlib import closing, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from deploy import verify_install
from hy2_lite.database import connect, migrate
from hy2_lite.subscriptions import render


class VerifyInstallTests(unittest.TestCase):
    def test_watch_requires_new_bytes_for_requested_user(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "panel.sqlite3"
            migrate(path)
            with connect(path, write=True) as db:
                db.execute("INSERT INTO users(user_id,display_name,origin,managed_at) VALUES ('test','Test','managed',0)")
                db.execute("INSERT INTO collector_state VALUES (1,1,1000,0,0,0)")
                db.execute("INSERT INTO traffic_hourly VALUES ('user','other',0,20,0,1000,0)")

            def finish_flow(seconds):
                with connect(path, write=True) as db:
                    db.execute("UPDATE collector_state SET at=2000")
                    db.execute("INSERT INTO traffic_hourly VALUES ('user','test',0,20,0,1000,0)")

            results = verify_install.Results()
            output = StringIO()
            with (patch.object(verify_install, "DB", path),
                  patch.object(verify_install.time, "sleep", side_effect=finish_flow) as sleep,
                  redirect_stdout(output)):
                verify_install.check_collector(results, "test", 10)
            sleep.assert_called_once()
            self.assertIn("Temporary account traffic recorded", output.getvalue())
            self.assertEqual(results.counts, {"PASS": 2, "FAIL": 0, "SKIPPED": 0})
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(verify_install.user_total(db, "test"), 20)

    def test_external_uses_matching_verified_subscription(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "profile.json"
            profile = render({"name": "test", "host": "8.8.8.8", "port": 24443,
                              "password": "temporary", "sni": "8.8.8.8"}, "json")
            path.write_text(profile, encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(verify_install.load_outbound(path, "8.8.8.8", 24443)["server_port"], 24443)
            with self.assertRaises(ValueError):
                verify_install.load_outbound(path, "8.8.8.8", 443)
            document = json.loads(profile)
            document["outbounds"][0]["tls"]["insecure"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_install.load_outbound(path, "8.8.8.8", 24443)
