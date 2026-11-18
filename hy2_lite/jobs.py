"""Execute one explicitly selected account job in the operator process."""
from dataclasses import asdict
import json
import secrets
import time

from .config_transaction import Rejected, RecoveryRequired, digest, encoded, locked
from .database import audit, connect
from .original_subscriptions import is_original_id


class JobRunner:
    def __init__(self, database, transaction, cipher, endpoint):
        self.database = database
        self.transaction = transaction
        self.cipher = cipher
        self.endpoint = endpoint

    def prepare(self, job_id):
        with connect(self.database, write=True) as db:
            job = db.execute("SELECT * FROM config_jobs WHERE id=?", (job_id,)).fetchone()
            if job is None:
                raise ValueError("Unknown configuration job")
            job = dict(job)
            if job["status"] in {"applied", "failed"}:
                return job
            other = db.execute("SELECT 1 FROM config_jobs WHERE status='running' AND id<>?", (job_id,)).fetchone()
            if other:
                raise RecoveryRequired("Resume the previously started configuration job")
            user = db.execute("SELECT * FROM users WHERE user_id=?", (job["user_id"],)).fetchone()
            subscription = db.execute("SELECT payload FROM managed_subscriptions WHERE user_id=?",
                                      (job["user_id"],)).fetchone()
            if job["status"] == "pending":
                action = job["action"]
                original = user is not None and user["origin"] == "original" and is_original_id(job["user_id"])
                if original:
                    subscription = db.execute(
                        "SELECT payload FROM disabled_original_credentials WHERE user_id=?", (job["user_id"],)
                    ).fetchone()
                valid_states = {"enable": {"disabled"}, "disable": {"enabled"}, "delete": {"enabled", "disabled"}}
                valid = (user is None and subscription is None) if action == "add" else (
                    action in valid_states and user is not None
                    and user["effective_state"] in valid_states[action]
                    and ((user["origin"] == "managed" and subscription is not None)
                         or (original and (action != "enable" or subscription is not None)))
                )
                if not valid:
                    db.execute("UPDATE config_jobs SET status='failed' WHERE id=?", (job_id,))
                    audit(db, int(time.time()), "local-operator", "user.change_failed", job["user_id"], "denied")
                    return dict(job, status="failed")
                before = self.transaction.read_live()[0]
                version = job["expected_version"] or digest(before)
                if action == "add":
                    item = dict(asdict(self.endpoint), name=job["user_id"],
                                password=secrets.token_urlsafe(32), token=secrets.token_urlsafe(32))
                    encrypted = self.cipher.encrypt(encoded(item))
                elif original and action == "disable":
                    try:
                        inbound, = [item for item in json.loads(before)["inbounds"]
                                    if item.get("tag") == self.transaction.tag and item.get("type") == "hysteria2"]
                        account, = [item for item in inbound["users"] if item["name"] == job["user_id"]]
                        password = account["password"]
                        if (set(account) != {"name", "password"} or not isinstance(password, str) or not password
                                or sum(item.get("password") == password for item in inbound["users"]) != 1):
                            raise ValueError
                    except (ValueError, KeyError, TypeError, AttributeError):
                        raise ValueError("Cannot safely preserve the original authentication entry") from None
                    encrypted = self.cipher.encrypt(encoded({"password": password}))
                elif original and action == "delete":
                    encrypted = self.cipher.encrypt(encoded({}))
                else:
                    encrypted = subscription[0]
                db.execute("UPDATE config_jobs SET status='running', apply_version=?, staged_payload=? WHERE id=?",
                           (version, encrypted, job_id))
                job.update(status="running", apply_version=version, staged_payload=encrypted)
            job["user_state"] = user["effective_state"] if user else None
            return job

    def run(self, job_id):
        with locked(self.transaction.state / "jobs.lock"):
            job = self.prepare(job_id)
            if job["status"] != "running":
                return job["status"]
            item = json.loads(self.cipher.decrypt(job["staged_payload"]))
            action, user_id = job["action"], job["user_id"]
            try:
                self.transaction.recover()
                if action == "delete" and job["user_state"] == "disabled":
                    self.transaction.check_absent(job["apply_version"], user_id)
                else:
                    password = item["password"] if action in {"add", "enable"} else None
                    applied = self.transaction.apply(job_id, job["apply_version"], action, user_id, password)
                    if digest(self.transaction.read_live()[0]) != applied:
                        raise RecoveryRequired("configuration changed before job finalization")
            except Rejected:
                self.finish(job, item, "failed")
                return "failed"
            self.finish(job, item, "applied")
            return "applied"

    def finish(self, job, item, status):
        now = int(time.time())
        action, user_id = job["action"], job["user_id"]
        with connect(self.database, write=True) as db:
            if status == "applied":
                if action == "add":
                    db.execute(
                        """INSERT INTO users(user_id, display_name, remark, origin, managed_at)
                        VALUES (?, ?, ?, 'managed', ?)""",
                        (user_id, job["display_name"], job["remark"] or "", now * 1000),
                    )
                    db.execute("INSERT INTO managed_subscriptions VALUES (?, ?, ?)",
                               (user_id, digest(item["token"].encode()), job["staged_payload"]))
                else:
                    state = {"enable": "enabled", "disable": "disabled", "delete": "deleted"}[action]
                    db.execute("UPDATE users SET effective_state=?, deleted_at=? WHERE user_id=?",
                               (state, now * 1000 if action == "delete" else None, user_id))
                    if is_original_id(user_id):
                        if action == "disable":
                            db.execute("INSERT INTO disabled_original_credentials VALUES (?, ?)",
                                       (user_id, job["staged_payload"]))
                        else:
                            db.execute("DELETE FROM disabled_original_credentials WHERE user_id=?", (user_id,))
                    if action == "delete":
                        db.execute("DELETE FROM managed_subscriptions WHERE user_id=?", (user_id,))
            db.execute("UPDATE config_jobs SET status=?, staged_payload=NULL, needs_review=0 WHERE id=?",
                       (status, job["id"]))
            audit(db, now, "local-operator", "user.change_" + status, user_id, status)
