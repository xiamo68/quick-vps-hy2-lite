"""Transactional sing-box user-list changes. Run in the operator process."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .original_subscriptions import is_original_id
from .user_ids import is_managed_id


class Rejected(RuntimeError):
    pass


class RecoveryRequired(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def atomic_write(path, data, metadata=None):
    fd, temporary = tempfile.mkstemp(prefix=".hy2-lite-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if metadata:
                if hasattr(os, "fchown") and (os.geteuid(), os.getegid()) != (metadata.st_uid, metadata.st_gid):
                    os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def locked(path):
    with path.open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def changed_config(before, tag, action, name, password):
    try:
        config = json.loads(before)
        matches = [item for item in config["inbounds"]
                   if item.get("tag") == tag and item.get("type") == "hysteria2"]
        if len(matches) != 1:
            raise ValueError()
        users = matches[0]["users"]
        names = [item["name"] for item in users]
        if len(names) != len(set(names)):
            raise ValueError()
    except (KeyError, TypeError, AttributeError, ValueError):
        raise Rejected("unsupported or ambiguous Hysteria2 configuration") from None
    if action in {"add", "enable"}:
        if name in names or any(item.get("password") == password for item in users):
            raise Rejected("user or credential already active")
        users.append({"name": name, "password": password})
    else:
        if name not in names:
            raise Rejected("user is not active")
        users.pop(names.index(name))
    return encoded(config)


class ConfigTransaction:
    def __init__(self, live, state, tag, check, reload, verify):
        self.live = Path(live).absolute()
        self.state = Path(state).absolute()
        if self.live.parent.resolve() == self.state.resolve() or self.state.is_symlink():
            raise ValueError("State must use a separate private directory")
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            mode = self.state.stat()
            if mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) & 0o077:
                raise ValueError("State directory must be owned by the operator and private")
        self.tag, self.check, self.reload, self.verify = tag, check, reload, verify
        self.pending = self.state / "pending.json"

    def read_live(self):
        metadata = self.live.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise Rejected("live configuration must be a regular file with one link")
        return self.live.read_bytes(), metadata

    def save_result(self, entry, status):
        atomic_write(self.state / (entry["job"] + ".result"), encoded(dict(entry, status=status)))

    def check_absent(self, version, name):
        with locked(self.state / "lock"):
            if self.pending.exists():
                raise RecoveryRequired("unfinished configuration transaction")
            before, _ = self.read_live()
            if digest(before) != version:
                raise Rejected("configuration version conflict")
            # Adding to an in-memory copy validates the target inbound and
            # rejects an account that is still present in the active config.
            changed_config(before, self.tag, "add", name, "")

    def apply(self, job, version, action, name, password=None):
        adding = action in {"add", "enable"}
        original = is_original_id(name)
        valid_password = (isinstance(password, str) and bool(password) if original else
                          bool(re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password or "")))
        if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", job)
                or not (original or is_managed_id(name))
                or (original and action == "add")
                or action not in {"add", "enable", "disable", "delete"}
                or (adding and not valid_password)
                or (not adding and password is not None)):
            raise Rejected("invalid managed user operation")
        with locked(self.state / "lock"):
            if self.pending.exists():
                raise RecoveryRequired("unfinished configuration transaction")
            result = self.state / (job + ".result")
            if result.exists():
                entry = json.loads(result.read_bytes())
                if (entry["action"], entry["name"]) != (action, name) or entry["status"] != "applied":
                    raise Rejected("job was already resolved")
                return entry["after"]
            before, metadata = self.read_live()
            if digest(before) != version:
                raise Rejected("configuration version conflict")
            after = changed_config(before, self.tag, action, name, password)
            candidate = self.state / "candidate.json"
            atomic_write(candidate, after)
            try:
                try:
                    self.check(candidate)
                except Exception:
                    raise Rejected("candidate check failed") from None
                if self.read_live()[0] != before:
                    raise Rejected("configuration changed while validating candidate")
                entry = dict(job=job, action=action, name=name, before=version, after=digest(after),
                             mode=stat.S_IMODE(metadata.st_mode), uid=metadata.st_uid, gid=metadata.st_gid)
                atomic_write(self.state / (job + ".backup"), before)
                atomic_write(self.pending, encoded(entry))
                try:
                    atomic_write(self.live, after, metadata)
                    self.reload()
                    self.verify(after, before)
                    self.save_result(entry, "applied")
                except Exception:
                    self.rollback(entry)
                    raise Rejected("candidate failed; previous configuration restored") from None
                self.pending.unlink()
                return entry["after"]
            finally:
                candidate.unlink(missing_ok=True)

    def rollback(self, entry):
        try:
            before = (self.state / (entry["job"] + ".backup")).read_bytes()
            current, metadata = self.read_live()
            if digest(before) != entry["before"] or digest(current) not in {entry["before"], entry["after"]}:
                raise RecoveryRequired("configuration or backup drift")
            if (stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid) != (
                entry["mode"], entry["uid"], entry["gid"]
            ):
                raise RecoveryRequired("configuration permissions changed")
            atomic_write(self.live, before, metadata)
            self.reload()
            self.verify(before, current)
            self.save_result(entry, "rolled_back")
            self.pending.unlink()
        except Exception:
            raise RecoveryRequired("configuration recovery requires operator review") from None

    def recover(self):
        with locked(self.state / "lock"):
            if not self.pending.exists():
                return False
            entry = json.loads(self.pending.read_bytes())
            result = self.state / (entry["job"] + ".result")
            if result.exists():
                final = json.loads(result.read_bytes())
                expected = final["after"] if final["status"] == "applied" else final["before"]
                if digest(self.read_live()[0]) != expected:
                    raise RecoveryRequired("resolved configuration drift")
                self.pending.unlink()
                return True
            self.rollback(entry)
            return True
