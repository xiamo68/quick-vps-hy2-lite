import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from hy2_lite.config_transaction import ConfigTransaction, Rejected, RecoveryRequired


class ConfigTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.live = self.root / "config.json"
        self.initial = json.dumps({"inbounds": [{"type": "hysteria2", "tag": "hy2-us", "users": [
            {"name": "user-91001", "password": "test-original"}
        ]}], "outbounds": [{"type": "direct"}]}).encode()
        self.live.write_bytes(self.initial)
        self.calls = []
        self.tx = ConfigTransaction(self.live, self.root / "state", "hy2-us",
                                    lambda path: self.calls.append(("check", path.name)),
                                    lambda: self.calls.append(("reload",)),
                                    self.verify)
        self.fail = False

    def verify(self, expected, previous):
        self.calls.append(("verify",))
        if self.fail and expected != self.initial:
            raise RuntimeError("probe failed")

    def apply(self, job, action, name, password=None):
        version = hashlib.sha256(self.live.read_bytes()).hexdigest()
        return self.tx.apply(job, version, action, name, password)

    def test_changes_only_target_and_replay_does_not_reload(self):
        self.apply("add", "add", "hy2-test", "A" * 32)
        users = json.loads(self.live.read_bytes())["inbounds"][0]["users"]
        self.assertEqual(users[0], {"name": "user-91001", "password": "test-original"})
        self.assertEqual(users[1]["name"], "hy2-test")
        self.apply("add", "add", "hy2-test", "A" * 32)
        self.assertEqual(self.calls.count(("reload",)), 1)
        self.apply("disable", "disable", "hy2-test")
        self.apply("enable", "enable", "hy2-test", "A" * 32)
        self.apply("delete", "delete", "hy2-test")
        self.assertEqual(json.loads(self.live.read_bytes()), json.loads(self.initial))

    def test_original_creation_and_drift_rejected_before_reload(self):
        with self.assertRaises(Rejected):
            self.apply("protected", "add", "user-91001", "test-original")
        with self.assertRaises(Rejected):
            self.tx.apply("stale", "0" * 64, "add", "hy2-test", "A" * 32)
        self.assertEqual(self.calls, [])

    def test_candidate_check_failure_does_not_write_live(self):
        def reject(_):
            raise RuntimeError("validator may contain secret")
        self.tx.check = reject
        with self.assertRaisesRegex(Rejected, "^candidate check failed$"):
            self.apply("invalid", "add", "hy2-test", "A" * 32)
        self.assertEqual(self.live.read_bytes(), self.initial)
        self.assertEqual(self.calls, [])

    def test_failed_probe_rolls_back_and_marks_terminal(self):
        self.fail = True
        with self.assertRaisesRegex(Rejected, "restored"):
            self.apply("failed", "add", "hy2-test", "A" * 32)
        self.assertEqual(self.live.read_bytes(), self.initial)
        self.assertEqual(self.calls.count(("reload",)), 2)
        with self.assertRaises(Rejected):
            self.apply("failed", "add", "hy2-test", "A" * 32)
        self.assertEqual(self.calls.count(("reload",)), 2)

    def test_interruption_requires_recovery(self):
        def interrupt():
            raise KeyboardInterrupt
        self.tx.reload = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.apply("interrupted", "add", "hy2-test", "A" * 32)
        with self.assertRaises(RecoveryRequired):
            self.apply("another", "add", "hy2-next", "B" * 32)
        self.tx.reload = lambda: self.calls.append(("reload",))
        self.assertTrue(self.tx.recover())
        self.assertEqual(self.live.read_bytes(), self.initial)
