from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image, ImageOps, UnidentifiedImageError

from xsignbot import releases
from xsignbot.core import (
    BotError, DRAFT_SECONDS, LOG, MAX_IPA, MAX_PHOTO, UPLOAD_SECONDS,
    active_lease, add_lease, app_root, button, keyboard, now, origin, random_id,
    read_ticket, say, store, telegram_file, ticket,
)
from xsignbot.signing import inspect_ipa


def draft_for(catalog, nonce=None):
    draft = catalog["draft"]
    if not draft or draft["expires"] <= now() or (nonce and draft["revision"] != nonce):
        raise BotError("مسودة التطبيق منتهية. افتح /admin وابدأ من جديد.")
    return draft


def editable(catalog, nonce=None):
    draft = draft_for(catalog, nonce)
    if draft.get("publishing", 0) > now():
        raise BotError("النشر جارٍ. انتظر اكتمال التحقق.")
    return draft


def discard(catalog, *assets):
    pending = catalog.setdefault("discarded", [])
    for asset in assets:
        if asset and asset["github_asset_id"] not in pending:
            pending.append(asset["github_asset_id"])


def clear_draft(catalog):
    draft = catalog["draft"]
    if draft:
        discard(catalog, draft.get("ipa"), draft.get("image"))
        catalog["draft"] = None


def cleanup_drafts():
    storage = store()
    snapshot = storage.catalog()
    draft = snapshot["draft"]
    if draft and max(draft["expires"], draft.get("publishing", 0)) <= now():
        def abandon(catalog):
            current = catalog["draft"]
            if current and max(current["expires"], current.get("publishing", 0)) <= now():
                clear_draft(catalog)

        storage.edit(abandon)
        snapshot = storage.catalog()
    for asset_id in snapshot.get("discarded", []):
        releases.delete_id(asset_id)

        def finish(catalog):
            pending = catalog.get("discarded", [])
            if asset_id in pending:
                pending.remove(asset_id)

        storage.edit(finish)


def status(chat, draft):
    name = draft["name"] or "لم يُحدد"
    uploaded = "✓" if draft.get("ipa") else "…"
    image = "✓" if draft.get("image") or draft.get("previous_image") else "…"
    rev = draft["revision"]
    token = ticket("upload", {"draft": rev}, min(UPLOAD_SECONDS, draft["expires"] - now()))
    instructions = ("ارفع IPA الجديد. يمكنك إرسال اسم أو صورة جديدة هنا."
                    if draft["previous_revision"] else "أرسل الاسم والصورة هنا ثم ارفع ملف IPA.")
    say(chat, f"اسم الزر وصفحة التثبيت: {name}\nIPA {uploaded}   الصورة {image}\n{instructions}",
        keyboard(
            (button("رفع IPA", url=f"{origin()}/api/admin/upload#t={token}"),),
            (button("نشر التطبيق", "green", callback_data=f"a:publish:{rev}"),),
            (button("إلغاء", "red", callback_data=f"a:cancel:{rev}"),),
        ))


def panel(chat):
    state = store().catalog()
    apps = sorted(state["apps"].values(), key=lambda app: (app["id"] != "xsign", app["name"]))
    body = "\n".join(f"• {app['name']}" for app in apps) or "ماكو تطبيقات منشورة بعد."
    rows = [
        (button("تحديث IPA لـ XSign", callback_data="a:xsign"),),
        (button("إضافة تطبيق", "green", callback_data="a:new"),),
    ]
    if any(record["id"] != "xsign" for record in apps):
        rows.append((button("تحديث التطبيقات المضافة", callback_data="a:updates"),))
    draft = state["draft"]
    if draft and draft["expires"] > now():
        rows.append((button("متابعة المسودة", callback_data="a:draft"),))
    if apps:
        rows.append((button("حذف تطبيق", "red", callback_data="a:list"),))
    if state["deleted"]:
        rows.append((button("تنظيف الحذف المعلّق", "red", callback_data="a:purge"),))
    say(chat, f"إدارة تطبيقات XSign\n\n{body}", keyboard(*rows))


def update_choices(chat):
    apps = store().catalog()["apps"].values()
    rows = [
        (button(record["name"], callback_data=f"a:edit:{record['id']}:{record['revision']}"),)
        for record in sorted(apps, key=lambda item: item["name"]) if record["id"] != "xsign"
    ]
    say(chat, "اختر التطبيق الذي تريد تحديثه.",
        keyboard(*rows, (button("رجوع", callback_data="a:panel"),)))


def new_draft(chat, app_id, expected_revision=None):
    revision, generation = random_id(), random_id()

    def change(catalog):
        old_draft = catalog["draft"]
        if old_draft and old_draft.get("publishing", 0) > now():
            raise BotError("النشر جارٍ. انتظر اكتمال التحقق.")
        if old_draft and old_draft["expires"] > now():
            raise BotError("عندك مسودة حالية. تابعها أو ألغها من /admin.")
        previous = catalog["apps"].get(app_id)
        if expected_revision and (previous is None or previous["revision"] != expected_revision):
            raise BotError("التطبيق تغيّر أو حُذف. افتح قائمة التحديث من جديد.")
        if previous is None and len(catalog["apps"]) >= 8:
            raise BotError("الحد الحالي 8 تطبيقات منشورة. احذف تطبيقاً قبل الإضافة.")
        clear_draft(catalog)
        draft = {
            "id": app_id, "generation": previous["generation"] if previous else generation,
            "revision": revision, "previous_revision": previous["revision"] if previous else None,
            "name": previous["name"] if previous else ("XSign" if app_id == "xsign" else ""),
            "previous_image": previous["image"] if previous else None,
            "expires": now() + DRAFT_SECONDS,
        }
        catalog["draft"] = draft
        return draft

    status(chat, store().edit(change))


def update_draft(chat, message):
    catalog = store().catalog()
    draft = catalog["draft"]
    if not draft or draft["expires"] <= now():
        return False
    rev = editable(catalog)["revision"]
    photo = (message.get("photo") or [None])[-1]
    text = (message.get("text") or "").strip()
    if photo:
        lease = random_id()

        def reserve(state):
            current = editable(state, rev)
            add_lease(state, lease, [app_root(current)], 120)

        store().edit(reserve)
        try:
            with TemporaryDirectory(prefix="xsign-image-") as tmp:
                path = Path(tmp) / "image"
                telegram_file(photo["file_id"], path, MAX_PHOTO)
                try:
                    with Image.open(path) as source:
                        if source.width * source.height > 20_000_000:
                            raise BotError("أرسل صورة أصغر.")
                        image = ImageOps.exif_transpose(source).convert("RGB")
                        image.thumbnail((640, 640))
                        result = Path(tmp) / "image.jpg"
                        image.save(result, "JPEG", quality=88)
                except (OSError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
                    raise BotError("الصورة غير صالحة. أرسلها كصورة في تيليغرام.") from exc
                asset = releases.upload(app_root(draft), f"image-{rev}-{lease}.jpg", result, "image/jpeg")

            def save(state):
                current = editable(state, rev)
                if current.get("image") != asset:
                    discard(state, current.get("image"))
                    current["image"] = asset
                return current

            try:
                updated = store().edit(save)
            except BotError:
                store().edit(lambda state: discard(state, asset))
                raise
            status(chat, updated)
        finally:
            release(lease)
        return True

    if text and not text.startswith("/") and len(text) <= 64:
        def rename(state):
            current = editable(state, rev)
            current["name"] = " ".join(text.split())
            return current
        status(chat, store().edit(rename))
    else:
        say(chat, "أرسل اسماً حتى 64 حرفاً، أو أرسل صورة، أو افتح /admin.")
    return True


def validate_upload(raw_ticket, size):
    if not 0 < size <= MAX_IPA:
        raise BotError("الحد الأعلى للـIPA هو 250 MiB.")
    rev = read_ticket("upload", raw_ticket)["draft"]
    return editable(store().catalog(), rev)


def finish_upload(draft, path):
    rev = draft["revision"]
    metadata = inspect_ipa(path)
    lease = random_id()

    def reserve(catalog):
        current = editable(catalog, rev)
        add_lease(catalog, lease, [app_root(current)], 300)

    store().edit(reserve)
    try:
        source = releases.upload(
            app_root(draft), f"base-{rev}-{lease}.ipa", path, "application/octet-stream",
        )

        def save(catalog):
            current = editable(catalog, rev)
            discard(catalog, current.get("ipa"))
            current["ipa"] = source
            current["metadata"] = metadata

        try:
            store().edit(save)
        except BotError:
            store().edit(lambda catalog: discard(catalog, source))
            raise
    finally:
        release(lease)


def release(lease):
    store().edit(lambda catalog: catalog["leases"].pop(lease, None))


def reserve_publish(rev):
    lease = random_id()

    def claim(state):
        draft = editable(state, rev)
        if not draft.get("name") or not draft.get("ipa") or not (draft.get("image") or draft.get("previous_image")):
            raise BotError("أكمل اسم الزر والصورة ورفع IPA قبل النشر.")
        draft["publishing"] = now() + 600
        draft["expires"] = max(draft["expires"], draft["publishing"])
        add_lease(state, lease, [app_root(draft)], 660)
        return draft

    return store().edit(claim), lease


def unlock_publish(draft, lease):
    def unlock(state):
        active = state["draft"]
        if active and active["revision"] == draft["revision"] and active.get("publishing") == draft["publishing"]:
            active.pop("publishing", None)
        state["leases"].pop(lease, None)
    store().edit(unlock)


def publish(chat, draft, lease):
    rev = draft["revision"]
    try:
        current = store().catalog()["draft"]
        if not current or current["revision"] != rev or current.get("publishing") != draft["publishing"]:
            return
        if current["publishing"] <= now():
            raise BotError("انتهت مهلة النشر. أعد المحاولة من لوحة الأدمن.")
        metadata = draft["metadata"]
        image = draft.get("image") or draft["previous_image"]

        def commit(catalog):
            current = draft_for(catalog, rev)
            if current.get("publishing") != draft["publishing"] or current["publishing"] <= now():
                raise BotError("انتهت مهلة النشر. حاول من لوحة الأدمن.")
            previous = catalog["apps"].get(draft["id"])
            if (previous["revision"] if previous else None) != draft["previous_revision"]:
                raise BotError("التطبيق تغيّر أثناء التحقق. افتح لوحة الأدمن.")
            record = {k: draft[k] for k in ("id", "generation", "revision", "name")}
            record.update(metadata, source=draft["ipa"], image=image)
            catalog["apps"][draft["id"]] = record
            catalog["draft"] = None

        store().edit(commit)
    except BotError as exc:
        say(chat, str(exc))
    except Exception as exc:
        LOG.warning("Publish failed: %s", type(exc).__name__)
        say(chat, "تعذر نشر التطبيق. المسودة محفوظة، حاول مرة أخرى.")
    else:
        say(chat, f"تم نشر {draft['name']}.\nمعرّف الحزمة: {metadata['bundle']}",
            keyboard((button("لوحة الأدمن", callback_data="a:panel"),)))
    finally:
        unlock_publish(draft, lease)


def delete_choices(chat):
    apps = store().catalog()["apps"].values()
    rows = [(button(app["name"], "red", callback_data=f"a:pick:{app['id']}"),) for app in apps]
    say(chat, "اختر التطبيق للحذف.", keyboard(*rows, (button("رجوع", callback_data="a:panel"),)))


def confirm_delete(chat, app_id):
    record = store().catalog()["apps"].get(app_id)
    if not record:
        raise BotError("التطبيق غير موجود.")
    say(chat, f"تحذف {record['name']} وكل نسخ IPA والصور وملفات التوقيع الخاصة به؟",
        keyboard(
            (button("تأكيد الحذف النهائي", "red", callback_data=f"a:delete:{app_id}:{record['revision']}"),),
            (button("رجوع", callback_data="a:list"),),
        ))


def mark_deleted(app_id, rev):
    def change(catalog):
        record = catalog["apps"].get(app_id)
        if not record or record["revision"] != rev:
            for root, deleted in catalog["deleted"].items():
                if root.startswith(f"{app_id}/") and deleted.get("revision") == rev:
                    return deleted["name"], root
            raise BotError("التطبيق تغيّر أو حُذف. افتح القائمة من جديد.")
        root = app_root(record)
        draft = catalog["draft"]
        if draft and app_root(draft) == root:
            catalog["draft"] = None
        del catalog["apps"][app_id]
        catalog["deleted"][root] = {"name": record["name"], "revision": rev, "at": now()}
        return record["name"], root

    return store().edit(change)


def purge_deleted(only=None):
    catalog = store().catalog()
    for root in catalog["deleted"]:
        if (only and root != only) or active_lease(catalog, root):
            continue
        releases.delete_app(root)
        store().wipe("results/" + root)
        def finish(state):
            state["deleted"].pop(root, None)
            state["leases"] = {key: lease for key, lease in state["leases"].items() if lease["expires"] > now()}
        store().edit(finish)
    return len(store().catalog()["deleted"])
