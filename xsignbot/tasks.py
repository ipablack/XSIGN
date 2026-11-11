import base64
import hashlib
import hmac
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xsignbot import releases
from xsignbot.core import BotError, LOG, StoreConflict, StoreUnavailable, b64, env, now, random_id, store

DISPATCH_SECONDS = 600
WORKER_LEASE = 330
QUEUE_KEY = "state/task-queue.json"
POLL_SECONDS = 5
WAKE = Event()


class QueueUnavailable(RuntimeError):
    pass


class RetryAfter(Exception):
    def __init__(self, delay):
        self.delay = max(1, delay)


def parallelism():
    try:
        count = int(os.environ.get("XSIGN_SIGN_WORKERS", "1"))
    except ValueError:
        count = 0
    if not 1 <= count <= 8:
        raise BotError("اضبط XSIGN_SIGN_WORKERS على رقم بين 1 و8.")
    return count


def cipher():
    key = hmac.new(env("HMAC_SECRET").encode(), b"xsign-queue-password-v1", hashlib.sha256).digest()
    return AESGCM(key)


def seal_password(chat, job, password):
    nonce = os.urandom(12)
    context = f"{chat}:{job}".encode()
    return b64(nonce + cipher().encrypt(nonce, password.encode(), context))


def open_password(chat, job, sealed):
    try:
        raw = base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4))
        return cipher().decrypt(raw[:12], raw[12:], f"{chat}:{job}".encode()).decode()
    except (InvalidTag, ValueError, TypeError) as exc:
        raise BotError("انتهت جلسة بيانات التوقيع. أعد إرسال الشهادة.") from exc


def expired(entry, timestamp):
    expiry = entry["expires"]
    return expiry is not None and expiry <= timestamp and entry.get("leased_until", 0) <= timestamp


def ready(entry, timestamp):
    return (
        "payload" in entry
        and (entry["expires"] is None or entry["expires"] > timestamp)
        and entry["due"] <= timestamp
        and entry.get("leased_until", 0) <= timestamp
    )


def prune(queue, timestamp):
    for key in [key for key, entry in queue.items() if expired(entry, timestamp)]:
        del queue[key]


def submit(items, retention=900):
    if not items:
        return
    timestamp = now()

    def add(queue):
        prune(queue, timestamp)
        for payload, key, delay in items:
            queue.setdefault(key, {
                "payload": payload, "due": timestamp + delay,
                "expires": timestamp + retention if retention is not None else None, "attempt": 0,
            })

    try:
        store().update(QUEUE_KEY, dict, add)
    except (BotError, StoreConflict, StoreUnavailable) as exc:
        raise QueueUnavailable("Could not persist the signing queue.") from exc
    WAKE.set()


def enqueue(payload, key, delay=0, retention=900):
    submit([(payload, key, delay)], retention)


def claim(available, limit):
    storage = store()
    snapshot, _ = storage.state(QUEUE_KEY, {})
    timestamp = now()
    if not any(ready(entry, timestamp) or expired(entry, timestamp) for entry in snapshot.values()):
        return []

    def reserve(queue):
        current = now()
        prune(queue, current)
        active = sum(entry.get("leased_until", 0) > current for entry in queue.values())
        capacity = min(available, max(0, limit - active))
        due = sorted(
            ((key, entry) for key, entry in queue.items() if ready(entry, current)),
            key=lambda item: item[1]["due"],
        )
        for _, entry in due[:capacity]:
            entry["lease"] = random_id()
            entry["leased_until"] = current + WORKER_LEASE
            entry["attempt"] += 1
        return due[:capacity]

    return storage.update(QUEUE_KEY, dict, reserve)


def execute(process, key, entry):
    retry_at = None
    try:
        process(entry["payload"], entry["attempt"])
    except RetryAfter as exc:
        retry_at = now() + exc.delay
    except releases.ReleaseRateLimit as exc:
        retry_at = now() + exc.retry_after
    except Exception as exc:
        LOG.warning("Task %s deferred: %s", entry["payload"]["kind"], type(exc).__name__)
        retry_at = now() + min(120, 12 * 2 ** min(entry["attempt"] - 1, 4))

    def settle(queue):
        active = queue.get(key)
        if not active or active.get("lease") != entry["lease"]:
            return
        expiry = active["expires"]
        if retry_at is not None and (expiry is None or retry_at < expiry):
            active["due"] = retry_at
            active.pop("lease", None)
            active.pop("leased_until", None)
        else:
            queue[key] = {"expires": expiry if expiry is not None else now() + 3600}

    try:
        store().update(QUEUE_KEY, dict, settle)
    except (BotError, StoreConflict, StoreUnavailable) as exc:
        LOG.warning("Task lease update deferred: %s", type(exc).__name__)


def serve(process, stop, limit):
    with ThreadPoolExecutor(max_workers=limit) as executor:
        running = set()
        while not stop.is_set():
            WAKE.clear()
            running = {future for future in running if not future.done()}
            slots = limit - len(running)
            if slots:
                try:
                    claimed = claim(slots, limit)
                except (BotError, StoreConflict, StoreUnavailable) as exc:
                    LOG.warning("Task queue unavailable: %s", type(exc).__name__)
                    claimed = []
                for key, entry in claimed:
                    future = executor.submit(execute, process, key, entry)
                    future.add_done_callback(lambda _: WAKE.set())
                    running.add(future)
            if not stop.is_set():
                WAKE.wait(POLL_SECONDS)
