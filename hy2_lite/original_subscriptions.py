"""Read-only reconciliation of existing Mihomo subscription files."""
import json
from pathlib import Path
import re
from urllib.parse import quote, urlsplit

import yaml

from .database import connect


def is_original_id(value):
    return isinstance(value, str) and re.fullmatch(r"user-[0-9]{1,12}", value) is not None


def match_original(config, directory, tag, endpoint):
    try:
        document = json.loads(config)
        inbound, = [item for item in document["inbounds"]
                    if item.get("tag") == tag and item.get("type") == "hysteria2"]
        users = [(item["name"], item["password"]) for item in inbound["users"]
                 if is_original_id(item.get("name"))]
        credentials = {password: name for name, password in users}
        expected = {name for name, _ in users}
        if len(users) != 11 or len(expected) != 11 or len(credentials) != 11 or any(
            not isinstance(password, str) or not password for password in credentials
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("Cannot identify 11 unique original credentials in the target inbound") from None

    matches = {}
    ambiguous = set()
    for path in sorted(Path(directory).iterdir()):
        if path.suffix.lower() not in {".yaml", ".yml"} or not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as source:
                data = source.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                raise ValueError
            doc = yaml.safe_load(data)
            candidates = {
                credentials[node["password"]] for node in doc["proxies"]
                if isinstance(node, dict) and node.get("type") == "hysteria2"
                and str(node.get("server", "")).lower() == endpoint.host.lower()
                and str(node.get("sni", endpoint.host)).lower() == endpoint.sni.lower()
                and str(node.get("port")) == str(endpoint.port)
                and isinstance(node.get("password"), str) and node["password"] in credentials
            }
        except (ValueError, KeyError, TypeError, yaml.YAMLError, OSError, RecursionError):
            continue
        if len(candidates) != 1:
            ambiguous.update(candidates)
            continue
        user, = candidates
        if user in matches:
            ambiguous.add(user)
        matches[user] = path.name

    for user in ambiguous:
        matches.pop(user, None)
    if set(matches) != expected:
        raise ValueError(f"Matched {len(matches)}/11 original subscriptions uniquely")
    return matches


def save_original_urls(database, cipher, matches, base_url):
    url = urlsplit(base_url)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.query or url.fragment or not base_url.endswith("/")
            or len(matches) != 11 or not all(map(is_original_id, matches))):
        raise ValueError("Expected a complete match and an existing HTTPS subscription prefix ending in /")
    with connect(database, write=True) as db:
        originals = {row[0] for row in db.execute("SELECT user_id FROM users WHERE origin='original'")}
        if set(matches) != originals:
            raise ValueError("Import the 11 original user IDs before recording URLs")
        rows = [(user, cipher.encrypt((base_url + quote(filename, safe="")).encode()))
                for user, filename in sorted(matches.items())]
        db.executemany(
            "INSERT INTO original_subscriptions VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET url=excluded.url", rows,
        )


def original_url(database, cipher, user_id):
    with connect(database) as db:
        row = db.execute("SELECT url FROM original_subscriptions WHERE user_id=?", (user_id,)).fetchone()
    return cipher.decrypt(row[0]).decode() if row else None
