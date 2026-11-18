import hashlib
import hmac
import re

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp

from .database import connect


PASSWORDS = PasswordHasher()
IDLE_SECONDS = 30 * 60
SESSION_SECONDS = 12 * 60 * 60
LIMIT_SECONDS = 5 * 60
MAX_FAILURES = 5


def validate_password(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 256 or not password.strip():
        raise ValueError("Password must contain 8 to 256 characters.")


def create_admin(path, username, password):
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ValueError("Invalid administrator username.")
    validate_password(password)
    password_hash = PASSWORDS.hash(password)
    with connect(path, write=True) as db:
        if db.execute("SELECT 1 FROM admin").fetchone():
            raise ValueError("The administrator is already initialized.")
        db.execute("INSERT INTO admin(id, username, password_hash) VALUES (1, ?, ?)",
                   (username, password_hash))


def password_matches(password_hash, password):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        return PASSWORDS.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def session_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def consume_otp(db, admin, encrypted_secret, otp, now, cipher):
    if not isinstance(otp, str) or not re.fullmatch(r"[0-9]{6}", otp):
        return False
    secret = cipher.decrypt(encrypted_secret.encode()).decode()
    totp = pyotp.TOTP(secret)
    step = now // totp.interval
    last = admin["last_totp_step"]
    for candidate in (step, step - 1, step + 1):
        if (last is None or candidate > last) and hmac.compare_digest(
            totp.generate_otp(candidate), otp
        ):
            db.execute("UPDATE admin SET last_totp_step = ? WHERE id = 1", (candidate,))
            return True
    return False
