"""Managed subscription data and client exports."""
from dataclasses import dataclass
import json
import re
from urllib.parse import quote, urlencode

from .config_transaction import digest
from .database import connect


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    sni: str

    def __post_init__(self):
        for value in (self.host, self.sni):
            if len(value) > 253 or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.split(".")
            ):
                raise ValueError("Expected a DNS name or IPv4 address")
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid Hysteria2 port")


def lookup(path, cipher, *, user_id=None, token=None):
    if (user_id is None) == (token is None):
        raise ValueError("Supply either a user ID or a token")
    if token is not None and not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    field, value = ("user_id", user_id) if token is None else ("token_hash", digest(token.encode()))
    with connect(path) as db:
        row = db.execute(
            f"""SELECT s.payload FROM managed_subscriptions s JOIN users u USING(user_id)
            WHERE s.{field}=? AND u.effective_state='enabled'
              AND NOT EXISTS (SELECT 1 FROM config_jobs j
                              WHERE j.user_id=u.user_id AND j.status='running')""", (value,),
        ).fetchone()
    return json.loads(cipher.decrypt(row[0])) if row else None


def render(item, kind):
    if kind == "yaml":
        values = {
            "name": item["name"], "type": "hysteria2", "server": item["host"],
            "port": item["port"], "password": item["password"], "sni": item["sni"],
        }
        lines = [f"  - {key}: {json.dumps(value, ensure_ascii=False)}" if i == 0 else
                 f"    {key}: {json.dumps(value, ensure_ascii=False)}"
                 for i, (key, value) in enumerate(values.items())]
        return "\n".join(["proxies:", *lines, "mode: rule", "rules:",
                          f"  - {json.dumps('MATCH,' + item['name'])}", ""])
    if kind == "json":
        return json.dumps({
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080}],
            "outbounds": [{
                "type": "hysteria2", "tag": item["name"], "server": item["host"],
                "server_port": item["port"], "password": item["password"],
                "tls": {"enabled": True, "server_name": item["sni"]},
            }],
        }, indent=2) + "\n"
    if kind == "uri":
        auth = quote(item["password"], safe="")
        return (f"hysteria2://{auth}@{item['host']}:{item['port']}?"
                + urlencode({"sni": item["sni"]}) + "#" + quote(item["name"], safe=""))
    raise ValueError("Unsupported subscription format")
