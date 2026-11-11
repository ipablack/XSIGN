import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from functools import lru_cache
from urllib.parse import quote, urlsplit

import httpx
LOG = logging.getLogger("xsign")
MAX_IPA = 250 * 1024 * 1024
MAX_PHOTO = 4 * 1024 * 1024
MAX_CERT = 2 * 1024 * 1024
UPLOAD_SECONDS = 900
DRAFT_SECONDS = 3600
INSTALL_SECONDS = 900
CATALOG_KEY = "state/catalog.json"
NO_CACHE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
COLOR = {"blue": "primary", "green": "success", "red": "danger"}


class BotError(Exception):
    """A message safe to show to a Telegram user."""


class MissingObject(Exception):
    pass


class StoreConflict(Exception):
    pass


class StoreUnavailable(Exception):
    pass


def random_id():
    return secrets.token_hex(8)


def now():
    return int(time.time())


def app_root(record):
    return f"{record['id']}/{record['generation']}/"


def active_lease(catalog, root):
    return any(root in lease["roots"] and lease["expires"] > now() for lease in catalog["leases"].values())


def add_lease(catalog, key, roots, seconds):
    catalog["leases"] = {k: v for k, v in catalog["leases"].items() if v["expires"] > now()}
    catalog["leases"][key] = {"roots": roots, "expires": now() + seconds}


def catalog_default():
    return {"apps": {}, "deleted": {}, "leases": {}, "draft": None, "discarded": []}


def env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise BotError(f"إعداد البوت ناقص: {name}")
    return value


def admin_id():
    value = os.environ.get("ADMIN_ID", "").strip()
    if re.fullmatch(r"[1-9][0-9]{0,15}", value):
        return int(value)
    return None


@lru_cache(maxsize=1)
def origin():
    raw = env("APP_DOMAIN").rstrip("/")
    parts = urlsplit(raw if "://" in raw else "https://" + raw)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.path or parts.query or parts.fragment:
        raise BotError("اضبط APP_DOMAIN على نطاق HTTPS للبوت.")
    return f"https://{parts.netloc}"


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def ticket(kind, payload, ttl):
    data = b64(json.dumps({"kind": kind, "exp": now() + ttl, **payload}, separators=(",", ":")).encode())
    sig = hmac.new(env("HMAC_SECRET").encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"


def read_ticket(kind, value):
    try:
        if len(value) > 2048:
            raise ValueError
        data, signature = value.split(".", 1)
        expected = hmac.new(env("HMAC_SECRET").encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)))
        if payload["kind"] != kind or payload["exp"] <= now():
            raise ValueError
        return payload
    except (TypeError, ValueError, KeyError) as exc:
        raise BotError("الرابط غير صالح أو انتهت صلاحيته.") from exc


def button(text, color="blue", **action):
    return {"text": text, "style": COLOR[color], **action}


def keyboard(*rows):
    return {"inline_keyboard": [list(row) for row in rows]}


@lru_cache(maxsize=1)
def telegram_client():
    return httpx.Client(timeout=httpx.Timeout(12, connect=5))


def telegram(method, **payload):
    url = f"https://api.telegram.org/bot{env('BOT_TOKEN')}/{method}"
    try:
        with_photo = isinstance(payload.get("photo"), bytes)
        if with_photo:
            photo = payload.pop("photo")
            data = {key: json.dumps(val, ensure_ascii=False) if isinstance(val, dict) else str(val) for key, val in payload.items()}
            request = {"data": data, "files": {"photo": ("app.jpg", photo, "image/jpeg")}}
        else:
            request = {"json": payload}
        for attempt in range(3):
            response = telegram_client().post(url, **request)
            data = response.json()
            if response.is_success and data.get("ok"):
                return data["result"]
            retry = data.get("parameters", {}).get("retry_after")
            if response.status_code != 429 or not isinstance(retry, int) or not 0 < retry <= 8 or attempt == 2:
                LOG.warning("Telegram %s returned %s", method, response.status_code)
                break
            time.sleep(retry + secrets.randbelow(350) / 1000)
    except (httpx.HTTPError, ValueError, KeyError):
        LOG.warning("Telegram %s failed", method)
    raise BotError("تعذر الاتصال بتيليغرام.")


def say(chat, text, markup=None):
    kwargs = {"reply_markup": markup} if markup else {}
    return telegram("sendMessage", chat_id=chat, text=text, **kwargs)


def telegram_file(file_id, destination, limit):
    file = telegram("getFile", file_id=file_id)
    if file.get("file_size", 0) > limit or not file.get("file_path"):
        raise BotError("حجم الملف يتجاوز الحد المسموح.")
    token = env("BOT_TOKEN")
    path = quote(file["file_path"], safe="/")
    try:
        with telegram_client().stream("GET", f"https://api.telegram.org/file/bot{token}/{path}") as response:
            response.raise_for_status()
            size = 0
            with destination.open("wb") as out:
                for chunk in response.iter_bytes(128 * 1024):
                    size += len(chunk)
                    if size > limit:
                        raise BotError("حجم الملف يتجاوز الحد المسموح.")
                    out.write(chunk)
    except httpx.HTTPError as exc:
        raise BotError("تعذر تنزيل الملف من تيليغرام.") from exc


class Store:
    def __init__(self):
        directory = Path(os.environ.get("XSIGN_DATA_DIR", str(Path.home() / ".xsign")))
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "state.sqlite3"
        self.query("PRAGMA journal_mode=WAL")
        self.query(
            "CREATE TABLE IF NOT EXISTS xsign_state ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL, version TEXT NOT NULL, expires_at INTEGER"
            ") WITHOUT ROWID"
        )
        self.query("CREATE INDEX IF NOT EXISTS xsign_expiration ON xsign_state(expires_at)")

    def query(self, sql, params=()):
        try:
            with closing(sqlite3.connect(self.path, timeout=5, isolation_level=None)) as connection:
                connection.row_factory = sqlite3.Row
                cursor = connection.execute(sql, params)
                return {
                    "results": [dict(row) for row in cursor.fetchall()],
                    "meta": {"changes": cursor.rowcount},
                }
        except sqlite3.Error as exc:
            raise StoreUnavailable("Local SQLite storage is unavailable.") from exc

    def state(self, key, default):
        rows = self.query("SELECT value, version FROM xsign_state WHERE key = ?", [key])["results"]
        if not rows:
            return default, None
        return json.loads(rows[0]["value"]), rows[0]["version"]

    def update(self, key, factory, change):
        for _ in range(8):
            data, version = self.state(key, factory())
            result = change(data)
            value = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            expires = str(data["expires"]) if key.startswith("sessions/") else "0"
            if version is None:
                write = self.query(
                    "INSERT INTO xsign_state (key, value, version, expires_at) VALUES (?, ?, ?, NULLIF(?, '0')) "
                    "ON CONFLICT(key) DO NOTHING",
                    [key, value, random_id(), expires],
                )
            else:
                write = self.query(
                    "UPDATE xsign_state SET value = ?, version = ?, expires_at = NULLIF(?, '0') "
                    "WHERE key = ? AND version = ?",
                    [value, random_id(), expires, key, version],
                )
            if write["meta"]["changes"] == 1:
                return result
            time.sleep(secrets.randbelow(70) / 1000)
        raise StoreConflict

    def catalog(self):
        return self.state(CATALOG_KEY, catalog_default())[0]

    def edit(self, change):
        return self.update(CATALOG_KEY, catalog_default, change)

    def put(self, key, value):
        self.query(
            "INSERT INTO xsign_state (key, value, version) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, version = excluded.version",
            [key, json.dumps(value, ensure_ascii=False, separators=(",", ":")), random_id()],
        )

    def wipe(self, prefix):
        upper = prefix[:-1] + chr(ord(prefix[-1]) + 1)
        self.query("DELETE FROM xsign_state WHERE key >= ? AND key < ?", [prefix, upper])

    def prune_sessions(self):
        self.query("DELETE FROM xsign_state WHERE expires_at <= ?", [str(now())])


@lru_cache(maxsize=1)
def store():
    return Store()
