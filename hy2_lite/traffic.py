from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .database import connect

HOUR = 3_600_000
DAY = 24 * HOUR
BEIJING_OFFSET = 8 * HOUR
MAX_GAP = 15_000
BEIJING = timezone(timedelta(hours=8))


@dataclass(frozen=True)
class Connection:
    id: str
    user: str
    created_at: int
    upload: int
    download: int
    closed_at: int | None = None


@dataclass(frozen=True)
class Snapshot:
    epoch: int
    at: int
    upload: int
    download: int
    connections: tuple[Connection, ...] = ()
    interrupted: bool = False


def segments(start, end):
    while start < end:
        hour = start // HOUR * HOUR
        stop = min(end, hour + HOUR)
        yield hour, start, stop
        start = stop


def record(db, scope, subject, start, end, up=0, down=0, observed=False, partial=False):
    archived = db.execute("SELECT cutoff FROM maintenance_state").fetchone()
    if archived and start < archived[0]:
        # Earlier hours have already been archived. Attribute only the portion
        # still inside the hourly window, preserving its original proportion.
        if end <= archived[0]:
            return
        elapsed = archived[0] - start
        up -= up * elapsed // (end - start)
        down -= down * elapsed // (end - start)
        start = archived[0]
    for hour, left, right in segments(start, end):
        duration = end - start
        db.execute(
            """INSERT INTO traffic_hourly VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, subject, hour) DO UPDATE SET
                upload=upload+excluded.upload, download=download+excluded.download,
                covered=covered+excluded.covered, partial=max(partial, excluded.partial)""",
            (scope, subject, hour,
             up * (right - start) // duration - up * (left - start) // duration,
             down * (right - start) // duration - down * (left - start) // duration,
             (right - left) if observed else 0, partial),
        )


def measure_connections(db, sample, previous, baseline, users, partial):
    totals = [0, 0]
    uncertain = False
    epoch = sample.epoch
    for flow in sample.connections:
        old = db.execute("SELECT * FROM connection_offsets WHERE epoch=? AND id=?",
                         (epoch, flow.id)).fetchone()
        if flow.user not in users:
            continue
        if old and (old["user_id"] != flow.user or old["closed"]):
            uncertain |= old["user_id"] != flow.user
            if old["closed"] and old["at"] < sample.at:
                db.execute("UPDATE connection_offsets SET at=? WHERE epoch=? AND id=?",
                           (sample.at, epoch, flow.id))
            continue
        up, down = flow.upload, flow.download
        if old:
            up -= old["upload"]
            down -= old["download"]
            start = old["at"]
        elif flow.created_at >= baseline:
            start = flow.created_at
        else:
            uncertain = True
            if flow.closed_at is None:
                save_offset(db, sample, flow)
            continue
        if min(up, down) < 0:
            uncertain = True
            continue
        end = min(sample.at, flow.closed_at if flow.closed_at is not None else sample.at)
        if up or down:
            retroactive = start < previous
            uncertain |= retroactive
            record(db, "user", flow.user, min(start, end - 1), end, up, down,
                   partial=partial or retroactive)
            db.execute("UPDATE users SET last_active_at=max(coalesce(last_active_at, 0), ?) WHERE user_id=?",
                       (end, flow.user))
        totals[0] += up
        totals[1] += down
        save_offset(db, sample, flow)
    return tuple(totals), uncertain


def save_offset(db, sample, flow):
    db.execute(
        """INSERT INTO connection_offsets VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(epoch, id) DO UPDATE SET
            at=excluded.at, upload=excluded.upload, download=excluded.download, closed=excluded.closed""",
        (sample.epoch, flow.id, flow.user, sample.at, flow.upload, flow.download, flow.closed_at is not None),
    )


def ingest(path, sample):
    if min(sample.at, sample.upload, sample.download) < 0:
        raise ValueError("Invalid proxy observation")
    if len({flow.id for flow in sample.connections}) != len(sample.connections):
        raise ValueError("Duplicate connection IDs in snapshot")
    for flow in sample.connections:
        if (min(flow.created_at, flow.upload, flow.download) < 0 or flow.created_at > sample.at
                or flow.closed_at is not None and not flow.created_at <= flow.closed_at <= sample.at):
            raise ValueError("Invalid connection observation")

    with connect(path, write=True) as db:
        previous = db.execute("SELECT * FROM collector_state").fetchone()
        if previous and (sample.at <= previous["at"] or sample.epoch < previous["epoch"]):
            return False
        users = {row[0] for row in db.execute("SELECT user_id FROM users")}
        same_epoch = previous and sample.epoch == previous["epoch"]
        proxy = None
        if same_epoch:
            delta = sample.upload - previous["upload"], sample.download - previous["download"]
            if min(delta) >= 0:
                proxy = delta
        if proxy is None:
            db.execute("DELETE FROM connection_offsets")
            for flow in sample.connections:
                if flow.user in users:
                    save_offset(db, sample, flow)
            if previous:
                db.execute("INSERT INTO collector_events(start, end, reason) VALUES (?, ?, ?)",
                           (previous["at"], sample.at, "counter_reset" if same_epoch else "instance_changed"))
        else:
            start = previous["at"]
            gap = sample.interrupted or sample.at - start > MAX_GAP
            attributed, uncertain = measure_connections(db, sample, start, previous["baseline"], users, gap)
            partial = gap or uncertain or attributed != proxy
            record(db, "proxy", "", start, sample.at, *proxy, observed=True, partial=gap)
            for user in users:
                record(db, "user", user, start, sample.at, observed=not partial, partial=partial)
            if partial:
                db.execute("INSERT INTO collector_events(start, end, reason) VALUES (?, ?, ?)",
                           (start, sample.at, "collector_gap" if gap else "unreconciled"))
        db.execute(
            """INSERT INTO collector_state VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch, at=excluded.at,
                upload=excluded.upload, download=excluded.download, baseline=excluded.baseline""",
            (sample.epoch, sample.at, sample.upload, sample.download,
             previous["baseline"] if proxy is not None else sample.at),
        )
        return True


def hourly(path, scope, subject, start, end, *, db=None):
    if start < 0 or start % HOUR or end % HOUR or not 0 < end - start <= 31 * 24 * HOUR:
        raise ValueError("Expected aligned UTC hours within a 31-day range")
    with (connect(path) if db is None else nullcontext(db)) as db:
        buckets = {row["hour"]: row for row in db.execute(
            "SELECT * FROM traffic_hourly WHERE scope=? AND subject=? AND hour>=? AND hour<?",
            (scope, subject, start, end),
        )}
    result = []
    for hour in range(start, end, HOUR):
        row = buckets.get(hour)
        observed = row and (row["covered"] or row["upload"] or row["download"])
        if not observed:
            result.append(dict(hour=hour, upload=None, download=None, coverage="missing"))
        else:
            valid = row["covered"] == HOUR and not row["partial"]
            result.append(dict(hour=hour, upload=row["upload"], download=row["download"],
                               coverage="valid" if valid else "partial"))
    return result


def daily(path, scope, subject, start, end):
    for boundary in (start, end):
        if (boundary + 8 * HOUR) % (24 * HOUR):
            raise ValueError("Expected Beijing midnight boundaries")
    with connect(path) as db:
        db.execute("BEGIN")
        buckets = hourly(path, scope, subject, start, end, db=db)
        archive = {row["day"]: row for row in db.execute(
            "SELECT * FROM traffic_daily WHERE scope=? AND subject=? AND day>=? AND day<?",
            (scope, subject, start, end),
        )}
    result = []
    for index in range(0, len(buckets), 24):
        hours = buckets[index:index + 24]
        day = hours[0]["hour"]
        archived = archive.get(day)
        observed = [row for row in hours if row["coverage"] != "missing"]
        coverage = "missing"
        if archived and (archived["covered"] or archived["upload"] or archived["download"]):
            coverage = "valid" if archived["covered"] == DAY and not archived["partial"] else "partial"
            upload, download = archived["upload"], archived["download"]
        elif observed:
            coverage = "valid" if all(row["coverage"] == "valid" for row in hours) else "partial"
            upload = sum(row["upload"] for row in observed)
            download = sum(row["download"] for row in observed)
        else:
            upload = download = None
        result.append({
            "day": datetime.fromtimestamp(day / 1000, BEIJING).date().isoformat(),
            "upload": upload,
            "download": download,
            "coverage": coverage,
        })
    return result


def maintain(path, now):
    cutoff = (now - 90 * DAY + BEIJING_OFFSET) // DAY * DAY - BEIJING_OFFSET
    with connect(path, write=True) as db:
        state = db.execute("SELECT cutoff FROM maintenance_state").fetchone()
        if state and cutoff <= state[0]:
            return
        db.execute(
            """INSERT INTO traffic_daily
            SELECT scope, subject, ((hour + ?) / ?) * ? - ? AS day,
                   sum(upload), sum(download), sum(covered), max(partial)
            FROM traffic_hourly WHERE hour < ? GROUP BY scope, subject, day""",
            (BEIJING_OFFSET, DAY, DAY, BEIJING_OFFSET, cutoff),
        )
        db.execute(
            """INSERT INTO traffic_lifetime
            SELECT scope, subject, sum(upload), sum(download)
            FROM traffic_hourly WHERE hour < ? AND (covered > 0 OR upload > 0 OR download > 0)
            GROUP BY scope, subject
            ON CONFLICT(scope, subject) DO UPDATE SET
                upload=upload+excluded.upload, download=download+excluded.download""", (cutoff,),
        )
        db.execute("DELETE FROM traffic_hourly WHERE hour < ?", (cutoff,))
        db.execute("DELETE FROM traffic_daily WHERE day < ?", (now - 365 * DAY,))
        db.execute("DELETE FROM system_samples WHERE at < ?", (now - 7 * DAY,))
        db.execute("DELETE FROM collector_events WHERE end < ?", (now - 365 * DAY,))
        db.execute("DELETE FROM admin_audit_logs WHERE at < ?", (now - 365 * DAY,))
        db.execute("DELETE FROM connection_offsets WHERE at < ?", (cutoff,))
        db.execute("UPDATE collector_state SET baseline=max(baseline, ?)", (cutoff,))
        db.execute("INSERT OR REPLACE INTO maintenance_state VALUES (1, ?)", (cutoff,))


def lifetime(path, scope, subject):
    with connect(path) as db:
        row = db.execute(
            """SELECT sum(upload), sum(download) FROM (
                SELECT upload, download FROM traffic_lifetime WHERE scope=? AND subject=?
                UNION ALL
                SELECT upload, download FROM traffic_hourly WHERE scope=? AND subject=?
                    AND (covered > 0 OR upload > 0 OR download > 0)
            )""", (scope, subject, scope, subject),
        ).fetchone()
    return {"observed_upload": row[0], "observed_download": row[1]}
