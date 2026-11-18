"""Stable identifiers for managed accounts."""

import re
import unicodedata


def is_managed_id(value):
    if re.fullmatch(r"hy2-[a-z0-9][a-z0-9-]{0,58}", value):
        return True
    if not value.startswith("h2-"):
        return False
    label = value[3:]
    return (0 < len(label) <= 59 and label[0].isalnum() and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label))


def allocate_user_id(db, display):
    normalized = unicodedata.normalize("NFKC", display).casefold()
    label = "".join(character if character.isalnum() else "-" for character in normalized)
    label = re.sub("-+", "-", label).strip("-")[:59].rstrip("-") or "user"
    number = 1
    while True:
        suffix = f"-{number}" if number > 1 else ""
        candidate = "h2-" + label[:59 - len(suffix)].rstrip("-") + suffix
        if not db.execute(
            "SELECT 1 FROM users WHERE user_id=? UNION ALL "
            "SELECT 1 FROM config_jobs WHERE user_id=? AND action='add' LIMIT 1",
            (candidate, candidate),
        ).fetchone():
            return candidate
        number += 1
