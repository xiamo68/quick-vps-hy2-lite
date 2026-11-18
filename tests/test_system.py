from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hy2_lite.database import connect, migrate
from hy2_lite.system_metrics import counter_rate, save_sample, service_states
from hy2_lite.traffic import HOUR, daily, hourly, lifetime, maintain


class SystemTests(unittest.TestCase):
    def test_caddy_status_tracks_the_configured_edge_unit(self):
        for edge_load, edge_state, legacy_state, expected in (
            ("loaded", "active", "inactive", "active"),
            ("loaded", "failed", "active", "failed"),
            ("not-found", "inactive", "active", "active"),
        ):
            with self.subTest(edge_load=edge_load, edge_state=edge_state):
                with patch("hy2_lite.system_metrics.subprocess.run") as show:
                    show.return_value.stdout = (
                        "Id=sing-box.service\nLoadState=loaded\nActiveState=active\n\n"
                        f"Id=caddy.service\nLoadState=loaded\nActiveState={legacy_state}\n\n"
                        f"Id=hy2-lite-edge.service\nLoadState={edge_load}\nActiveState={edge_state}\n"
                    )
                    self.assertEqual(service_states(), {"sing-box.service": "active", "caddy.service": expected})

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "test.sqlite3"
        migrate(self.path)

    def test_counter_reset_and_network_rate(self):
        self.assertEqual(counter_rate(1000, 1400, 2000), 200)
        self.assertIsNone(counter_rate(1000, 10, 2000))
        self.assertIsNone(counter_rate(1000, 1000, 0))

    def test_samples_preserve_unknown_and_compute_rates(self):
        def sample(at, boot, rx, total):
            return dict(at=at, boot=boot, interface="eth0", rx=rx, tx=rx,
                        cpu_total=total, cpu_idle=total // 2, memory={}, swap={},
                        disk={}, uptime_seconds=1, services={})

        self.assertIsNone(save_sample(self.path, sample(1000, "a", 100, 100))["cpu_percent"])
        second = save_sample(self.path, sample(2000, "a", 250, 200))
        self.assertEqual((second["cpu_percent"], second["rx_bytes_per_second"]), (50, 150))
        self.assertIsNone(save_sample(self.path, sample(3000, "b", 500, 300))["rx_bytes_per_second"])

    def test_archive_keeps_daily_and_repeated_cleanup_does_not_double_count(self):
        with connect(self.path, write=True) as db:
            db.execute("INSERT INTO traffic_hourly VALUES ('proxy','',?,12,5,3600000,0)", (16 * HOUR,))
        now = 100 * 24 * HOUR
        maintain(self.path, now)
        maintain(self.path, now)
        self.assertEqual(hourly(self.path, "proxy", "", 16 * HOUR, 17 * HOUR)[0]["coverage"], "missing")
        row = daily(self.path, "proxy", "", 16 * HOUR, 40 * HOUR)[0]
        self.assertEqual((row["upload"], row["download"], row["coverage"]), (12, 5, "partial"))
        with connect(self.path) as db:
            self.assertEqual(db.execute("SELECT upload, download FROM traffic_lifetime").fetchone()[:], (12, 5))
        self.assertEqual(lifetime(self.path, "proxy", ""), {"observed_upload": 12, "observed_download": 5})
