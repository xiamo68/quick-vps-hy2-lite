"""Read the sing-box 1.14.4 native API over its loopback gRPC-Web transport."""
from collections import OrderedDict
from contextlib import closing, contextmanager
from dataclasses import replace
import http.client
import re
import struct
from threading import Event, Lock, Thread
import time

from .system_metrics import linux_sample, save_sample
from .traffic import Connection, Snapshot, ingest, maintain


def protobuf_fields(payload):
    position = 0

    def varint():
        nonlocal position
        result = 0
        for shift in range(0, 70, 7):
            if position == len(payload):
                raise ValueError("Truncated protobuf varint")
            byte = payload[position]
            position += 1
            result |= (byte & 127) << shift
            if byte < 128:
                return result
        raise ValueError("Invalid protobuf varint")

    while position < len(payload):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not number:
            raise ValueError("Invalid protobuf field number")
        if wire == 0:
            yield number, varint()
        elif wire == 2:
            length = varint()
            end = position + length
            if end > len(payload):
                raise ValueError("Truncated protobuf field")
            yield number, payload[position:end]
            position = end
        elif wire in (1, 5):
            position += 8 if wire == 1 else 4
            if position > len(payload):
                raise ValueError("Truncated protobuf field")
        else:
            raise ValueError("Unsupported protobuf wire type")


def read_frame(response):
    header = response.read(5)
    if len(header) != 5:
        raise ValueError("Native API returned no data frame")
    flag, size = struct.unpack(">BI", header)
    if flag or size > 16 * 1024 * 1024:
        raise ValueError("Unsupported native API frame")
    payload = response.read(size)
    if len(payload) != size:
        raise ValueError("Truncated native API frame")
    return payload


class NativeAPI:
    def __init__(self, port, token, inbound="hy2-us"):
        if not 1 <= port <= 65535 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            raise ValueError("Invalid native API port or token")
        self.port = port
        self.token = token
        self.inbound = inbound.encode()

    @contextmanager
    def stream(self, method, message=b"", timeout=5):
        frame = struct.pack(">BI", 0, len(message)) + message
        with closing(http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)) as client:
            client.request("POST", "/daemon.StartedService/" + method, frame, {
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/grpc-web+proto",
                "X-Grpc-Web": "1",
            })
            with closing(client.getresponse()) as response:
                if response.status != 200 or response.getheader("grpc-status", "0") != "0":
                    raise ValueError(f"Native API request rejected: {method}")
                yield response

    def read(self, method, message=b""):
        with self.stream(method, message) as response:
            return list(protobuf_fields(read_frame(response)))

    def epoch(self):
        started = dict(self.read("GetStartedAt")).get(1, 0)
        if not isinstance(started, int) or started <= 0:
            raise ValueError("Native API did not report a valid instance start time")
        return started

    def connections(self, events):
        for field, payload in events:
            if field != 1:
                continue
            event = dict(protobuf_fields(payload))
            if 3 not in event:
                continue
            item = dict(protobuf_fields(event[3]))
            if item.get(2) != self.inbound or not item.get(10):
                continue
            yield Connection(item[1].decode(), item[10].decode(), item[12],
                             item.get(16, 0), item.get(17, 0), item.get(13))

    def snapshot(self, interrupted=False):
        epoch = self.epoch()
        events = self.read("SubscribeConnections")
        if (2, 1) not in events:
            raise ValueError("Native API did not return an initial connection snapshot")
        connections = {flow.id: flow for flow in self.connections(events)}
        status = dict(self.read("SubscribeStatus"))
        at = time.time_ns() // 1_000_000
        if not status.get(5) or self.epoch() != epoch:
            raise ValueError("Native API traffic counters unavailable or instance changed during observation")
        return Snapshot(epoch, at, status.get(8, 0), status.get(9, 0),
                        tuple(connections.values()), interrupted)


class ClosedBuffer:
    def __init__(self, capacity=8192):
        self.capacity = capacity
        self.records = OrderedDict()
        self.lock = Lock()
        self.gap_at = float("-inf")

    def add(self, epoch, flow):
        with self.lock:
            self.records[(epoch, flow.id)] = flow
            if len(self.records) > self.capacity:
                self.records.popitem(last=False)
                self.gap_at = time.monotonic()

    def mark_gap(self):
        with self.lock:
            self.gap_at = time.monotonic()

    def read(self, epoch, at):
        with self.lock:
            return (
                tuple(flow for (generation, _), flow in self.records.items()
                      if generation == epoch and flow.closed_at <= at),
                self.gap_at > time.monotonic() - 15,
            )

    def acknowledge(self, epoch, flows):
        with self.lock:
            for flow in flows:
                key = epoch, flow.id
                if self.records.get(key) == flow:
                    del self.records[key]
            for key in tuple(self.records):
                if key[0] < epoch:
                    del self.records[key]


def merge_closed(sample, closed):
    flows = {flow.id: flow for flow in sample.connections}
    for flow in closed:
        if flow.closed_at <= sample.at:
            flows[flow.id] = flow
    return replace(sample, connections=tuple(flows.values()))


def read_closed(api, buffer, stop, ready=None):
    while not stop.is_set():
        started = time.monotonic()
        try:
            epoch = api.epoch()
            # Check instance identity without recycling a healthy stream.
            with api.stream("SubscribeConnections", timeout=30) as response:
                events = list(protobuf_fields(read_frame(response)))
                if (2, 1) not in events or api.epoch() != epoch:
                    raise ValueError("Connection stream instance changed during setup")
                next_epoch_check = time.monotonic() + 120
                while not stop.is_set():
                    now = time.monotonic()
                    if now >= next_epoch_check:
                        if api.epoch() != epoch:
                            raise ValueError("Connection stream instance changed")
                        next_epoch_check = now + 120
                    for flow in api.connections(events):
                        if flow.closed_at is not None:
                            buffer.add(epoch, flow)
                    if ready:
                        ready.set()
                    if stop.is_set():
                        break
                    events = list(protobuf_fields(read_frame(response)))
        except TimeoutError:
            # Idle streams can legitimately emit no events. The next snapshot
            # and proxy counter comparison still validate coverage.
            pass
        except (OSError, http.client.HTTPException, ValueError, KeyError):
            buffer.mark_gap()
        stop.wait(max(0, 1 - (time.monotonic() - started)))


def run_collector(path, api, once=False, interface=None):
    if once:
        ingest(path, api.snapshot())
        if interface:
            save_sample(path, linux_sample(interface))
        return
    stop = Event()
    buffer = ClosedBuffer()
    Thread(target=read_closed, args=(api, buffer, stop), daemon=True).start()
    interrupted = True
    system_due = maintenance_due = 0
    try:
        while True:
            start = time.monotonic()
            try:
                sample = api.snapshot(interrupted=interrupted)
                flows, gap = buffer.read(sample.epoch, sample.at)
                sample = merge_closed(replace(sample, interrupted=sample.interrupted or gap), flows)
                if ingest(path, sample):
                    buffer.acknowledge(sample.epoch, flows)
                interrupted = False
            except (OSError, http.client.HTTPException, ValueError, KeyError):
                interrupted = True
                print("Native API observation failed; retrying", flush=True)
            if interface and start >= system_due:
                system_due = start + 60
                try:
                    save_sample(path, linux_sample(interface))
                except (OSError, ValueError, KeyError):
                    print("Linux system metrics unavailable; retrying", flush=True)
            if start >= maintenance_due:
                maintain(path, time.time_ns() // 1_000_000)
                maintenance_due = start + 3600
            time.sleep(max(0, 5 - (time.monotonic() - start)))
    finally:
        stop.set()
