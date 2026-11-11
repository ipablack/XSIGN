import os
import re
import time
from functools import lru_cache
from urllib.parse import urlsplit

import httpx

from xsignbot.core import BotError, MAX_IPA, MissingObject, env

TAG = "xsign-bot-assets"
API = "https://api.github.com"
ROOT = re.compile(r"(?:xsign|[a-f0-9]{16})/[a-f0-9]{16}/\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class ReleaseError(RuntimeError):
    pass


class ReleaseRateLimit(ReleaseError):
    def __init__(self, retry_after):
        super().__init__("GitHub rate limit")
        self.retry_after = retry_after


def enabled():
    return bool(os.environ.get("GITHUB_REPOSITORY", "").strip())


@lru_cache(maxsize=1)
def client():
    return httpx.Client(timeout=httpx.Timeout(40, connect=6))


def request_headers(accept="application/vnd.github+json"):
    return {
        "Authorization": f"Bearer {env('GITHUB_TOKEN')}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2026-03-10",
    }


def check(response, operation):
    retry = response.headers.get("retry-after", "")
    reset = response.headers.get("x-ratelimit-reset", "")
    if response.status_code in {403, 429}:
        if retry.isdigit():
            raise ReleaseRateLimit(max(1, int(retry)))
        if response.headers.get("x-ratelimit-remaining") == "0" and reset.isdigit():
            raise ReleaseRateLimit(max(1, int(reset) - int(time.time())))
        if response.status_code == 429 or "secondary rate limit" in response.text.casefold():
            raise ReleaseRateLimit(60)
    if response.is_error:
        raise ReleaseError(f"GitHub {operation}: HTTP {response.status_code}")
    return response


def listing(path):
    page = 1
    while True:
        response = client().get(f"{API}{path}", headers=request_headers(),
                                params={"per_page": 100, "page": page})
        rows = check(response, "list").json()
        yield from rows
        if len(rows) < 100:
            return
        page += 1


@lru_cache(maxsize=2)
def release_context(_minute):
    repo = env("GITHUB_REPOSITORY")
    if not REPO.fullmatch(repo):
        raise BotError("اضبط GITHUB_REPOSITORY على owner/repo.")
    path = f"/repos/{repo}"
    data = check(client().get(f"{API}{path}", headers=request_headers()), "repository").json()
    if not data.get("private") or data.get("visibility", "private") != "private":
        raise BotError("اجعل مستودع GitHub خاصاً قبل رفع التطبيقات.")
    matches = [entry for entry in listing(f"{path}/releases") if entry["tag_name"] == TAG]
    if len(matches) != 1 or not matches[0]["draft"]:
        raise BotError(f"جهّز Release مسوّدة واحدة باسم الوسم {TAG} داخل نفس المستودع.")
    return path, matches[0]["id"]


def context():
    return release_context(int(time.monotonic() // 60))


def asset_prefix(root):
    if not ROOT.fullmatch(root):
        raise ValueError("Invalid app storage root")
    return f"xsignbot-{root.strip('/').replace('/', '-')}-"


def assets():
    path, release_id = context()
    return listing(f"{path}/releases/{release_id}/assets")


def delete_id(asset_id):
    path, _ = context()
    response = client().delete(f"{API}{path}/releases/assets/{int(asset_id)}", headers=request_headers())
    if response.status_code != 404:
        check(response, "delete asset")


def delete_app(root):
    prefix = asset_prefix(root)
    matches = [item["id"] for item in assets() if item["name"].startswith(prefix)]
    for asset_id in matches:
        delete_id(asset_id)


def delete_signed(root, job):
    name = f"{asset_prefix(root)}signed-{job}.ipa"
    matches = [item["id"] for item in assets() if item["name"] == name]
    for asset_id in matches:
        delete_id(asset_id)


def ref(item):
    return {"github_asset_id": item["id"], "size": item["size"]}


def upload(root, suffix, file, media_type):
    size = file.stat().st_size
    if not 0 < size <= MAX_IPA:
        raise BotError("الملف يتجاوز حد حجم البوت.")
    name = asset_prefix(root) + suffix
    path, release_id = context()
    url = f"https://uploads.github.com{path}/releases/{release_id}/assets"
    headers = {**request_headers(), "Content-Type": media_type, "Content-Length": str(size)}

    def send():
        with file.open("rb") as body:
            chunks = iter(lambda: body.read(256 * 1024), b"")
            return client().post(url, params={"name": name}, headers=headers, content=chunks)

    response = send()
    if response.status_code in {422, 502}:
        # GitHub may leave an empty starter asset when an upload is interrupted.
        for item in assets():
            if item["name"] != name:
                continue
            if item.get("state") == "uploaded" and item["size"] == size:
                return ref(item)
            if item.get("state") == "starter":
                delete_id(item["id"])
                response = send()
            break
    return ref(check(response, "upload asset").json())


class ReleaseBody:
    def __init__(self, response):
        self.response = response

    def iter_chunks(self, size):
        yield from self.response.iter_raw(size)

    def read(self):
        return self.response.read()

    def close(self):
        self.response.close()


def asset_object(reference, **kwargs):
    path, _ = context()
    url = f"{API}{path}/releases/assets/{int(reference['github_asset_id'])}"
    stream_headers = {"Accept-Encoding": "identity"}
    if "Range" in kwargs:
        stream_headers["Range"] = kwargs["Range"]
    headers = {**request_headers("application/octet-stream"), **stream_headers}
    response = client().send(client().build_request("GET", url, headers=headers), stream=True)
    if response.is_redirect:
        location = response.headers.get("location", "")
        response.close()
        target = urlsplit(location)
        if target.scheme != "https" or not target.hostname or target.username or target.password:
            raise ReleaseError("Invalid GitHub asset redirect")
        # The storage redirect is signed by GitHub. It never receives our repository token.
        request = client().build_request("GET", location, headers=stream_headers)
        response = client().send(request, stream=True)
    if response.status_code == 404:
        response.close()
        raise MissingObject
    if response.status_code == 416:
        response.close()
        return {"RangeError": True}
    if response.status_code not in {200, 206}:
        try:
            response.read()
            check(response, "download asset")
            raise ReleaseError(f"GitHub download asset: HTTP {response.status_code}")
        finally:
            response.close()
    try:
        length = int(response.headers.get("content-length", reference["size"]))
        result = {"Body": ReleaseBody(response), "ContentLength": length}
        if "content-range" in response.headers:
            result["ContentRange"] = response.headers["content-range"]
        return result
    except (ValueError, KeyError):
        response.close()
        raise


def asset_head(reference):
    path, _ = context()
    asset_id = int(reference["github_asset_id"])
    response = client().get(f"{API}{path}/releases/assets/{asset_id}", headers=request_headers())
    if response.status_code == 404:
        raise MissingObject
    asset = check(response, "asset metadata").json()
    return {"ContentLength": asset["size"]}


def asset_bytes(reference):
    result = asset_object(reference)
    with_body = result["Body"]
    try:
        return with_body.read()
    finally:
        with_body.close()


def download(reference, destination):
    result = asset_object(reference)
    body = result["Body"]
    try:
        if result["ContentLength"] > MAX_IPA:
            raise BotError("حجم الملف يتجاوز الحد المسموح.")
        with destination.open("wb") as output:
            for chunk in body.iter_chunks(256 * 1024):
                output.write(chunk)
    finally:
        body.close()
