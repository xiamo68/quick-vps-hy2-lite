import tempfile
import unittest
from pathlib import Path

from hy2_lite.database import connect, migrate
from hy2_lite.traffic import Connection, Snapshot, daily, ingest, hourly

HOUR = 3_600_000


class TrafficTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "state.sqlite3"
        migrate(self.path)
        with connect(self.path) as db:
            db.execute("INSERT INTO users(user_id, display_name, origin, managed_at) VALUES ('u','U','original',0)")

    def sample(self, at, total, connections=(), epoch=1):
        return ingest(self.path, Snapshot(epoch, at, total, 0, tuple(connections)))

    def test_baseline_replay_and_cross_hour(self):
        self.sample(HOUR - 2000, 10, [Connection("one", "u", 0, 10, 0)])
        record = Connection("one", "u", 0, 19, 0)
        self.sample(HOUR + 2000, 19, [record])
        self.sample(HOUR + 2000, 19, [record])
        rows = hourly(self.path, "user", "u", 0, 2 * HOUR)
        self.assertEqual([row["upload"] for row in rows], [4, 5])
        self.assertEqual([row["coverage"] for row in rows], ["partial", "partial"])

    def test_proxy_difference_does_not_become_user_bytes(self):
        self.sample(0, 100)
        self.sample(5000, 120, [Connection("new", "u", 10, 5, 0, 1000)])
        self.assertEqual(hourly(self.path, "user", "u", 0, HOUR)[0]["upload"], 5)
        self.assertEqual(hourly(self.path, "proxy", "", 0, HOUR)[0]["upload"], 20)
        with connect(self.path) as db:
            self.assertEqual(db.execute("SELECT reason FROM collector_events").fetchone()[0], "unreconciled")

    def test_epoch_reset_and_empty_time(self):
        self.sample(0, 0)
        self.sample(1000, 7, [Connection("one", "u", 10, 7, 0)])
        self.sample(2 * HOUR, 3, [Connection("other", "u", 2 * HOUR - 10, 3, 0)], epoch=2)
        rows = hourly(self.path, "user", "u", 0, 3 * HOUR)
        self.assertEqual([row["upload"] for row in rows], [7, None, None])

    def test_full_hour_of_observed_zero_is_valid(self):
        self.sample(0, 0)
        for at in range(5000, HOUR + 1, 5000):
            self.sample(at, 0)
        row = hourly(self.path, "user", "u", 0, HOUR)[0]
        self.assertEqual((row["upload"], row["download"], row["coverage"]), (0, 0, "valid"))

    def test_daily_split_uses_beijing_midnight(self):
        midnight = 40 * HOUR
        self.sample(midnight - 1000, 0)
        self.sample(midnight + 1000, 9, [Connection("one", "u", midnight - 1000, 9, 0)])
        rows = daily(self.path, "user", "u", 16 * HOUR, 88 * HOUR)
        self.assertEqual([(row["day"], row["upload"], row["coverage"]) for row in rows],
                         [("1970-01-02", 4, "partial"), ("1970-01-03", 5, "partial"),
                          ("1970-01-04", None, "missing")])
