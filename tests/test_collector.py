import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import patch

from hy2_lite.collector import ClosedBuffer, merge_closed, read_closed
from hy2_lite.database import connect, migrate
from hy2_lite.traffic import Connection, Snapshot, hourly, ingest


class CollectorTests(unittest.TestCase):
    def test_healthy_stream_keeps_receiving_after_previous_rotation_deadline(self):
        stop, buffer = Event(), ClosedBuffer()
        flow = Connection("short", "u", 120_100, 12, 22, 120_200)
        elapsed = [0]
        subscriptions = []

        class API:
            def epoch(self):
                return 1

            @contextmanager
            def stream(self, method, timeout):
                subscriptions.append(method)
                yield iter((b"\x10\x01", b"\x08\x01"))

            def connections(self, events):
                if (1, 1) in events:
                    stop.set()
                    yield flow

        def frame(response):
            payload = next(response)
            if payload == b"\x08\x01":
                elapsed[0] = 121
            return payload

        with patch("hy2_lite.collector.read_frame", side_effect=frame), \
                patch("hy2_lite.collector.time.monotonic", side_effect=lambda: elapsed[0]):
            read_closed(API(), buffer, stop)
            self.assertEqual(buffer.read(1, 121_000), ((flow,), False))
        self.assertEqual(subscriptions, ["SubscribeConnections"])

        with TemporaryDirectory() as folder:
            path = Path(folder) / "isolated.sqlite3"
            migrate(path)
            with connect(path, write=True) as db:
                db.execute("INSERT INTO users(user_id, display_name, origin, managed_at) "
                           "VALUES ('u', 'Test user', 'original', 0)")
            ingest(path, Snapshot(1, 120_000, 0, 0, ()))
            flows, gap = buffer.read(1, 125_000)
            for at in (125_000, 130_000):
                ingest(path, merge_closed(Snapshot(1, at, 12, 22, (), gap), flows))
            row = hourly(path, "user", "u", 0, 3_600_000)[0]
            self.assertEqual((row["upload"], row["download"]), (12, 22))
            with connect(path) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM collector_events").fetchone()[0], 0)

    def test_final_bytes_override_active_snapshot_and_wait_for_timestamp(self):
        active = Connection("a", "u", 1, 10, 20)
        closed = Connection("a", "u", 1, 12, 22, 9)
        future = Connection("b", "u", 2, 5, 8, 12)
        sample = Snapshot(1, 10, 12, 22, (active,))
        merged = merge_closed(sample, (closed, future))
        self.assertEqual(merged.connections, (closed,))

    def test_buffer_survives_reads_and_bounds_overflow(self):
        buffer = ClosedBuffer(capacity=1)
        a = Connection("a", "u", 1, 12, 22, 9)
        b = Connection("b", "u", 2, 5, 8, 12)
        buffer.add(1, a)
        buffer.add(1, b)
        self.assertEqual(buffer.read(1, 20)[0], (b,))
        flows, interrupted = buffer.read(1, 20)
        self.assertTrue(interrupted)
        buffer.acknowledge(1, flows)
        self.assertEqual(buffer.read(1, 20)[0], ())

    def test_reader_separates_reloaded_instance(self):
        buffer = ClosedBuffer()
        a = Connection("a", "u", 1, 12, 22, 9)
        buffer.add(1, a)
        self.assertEqual(buffer.read(2, 20)[0], ())
