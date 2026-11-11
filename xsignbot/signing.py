import plistlib
import re
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from stat import S_ISLNK

from asn1crypto import cms

from xsignbot.core import BotError

APP_INFO = re.compile(r"Payload/[^/]+\.app/Info\.plist\Z")
BUNDLE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\Z")
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
SIGNER = Path(__file__).resolve().parents[1] / "bin" / "zsign"


def inspect_ipa(path):
    try:
        with zipfile.ZipFile(path) as ipa:
            infos = ipa.infolist()
            expanded = sum(entry.file_size for entry in infos)
            if len(infos) > 60_000 or expanded > MAX_EXPANDED:
                raise BotError("حجم محتويات IPA بعد الفك يتجاوز الحد.")
            for entry in infos:
                filename = entry.filename
                if (filename.startswith("/") or "\\" in filename or ".." in filename.split("/")
                        or S_ISLNK(entry.external_attr >> 16)):
                    raise BotError("ملف IPA يحتوي مسارات أرشيف غير آمنة.")
                if filename.lower().endswith(("/signing-assets/xsign/cert.p12", "/signing-assets/xsign/cert.txt")):
                    raise BotError("ارفع IPA أصلياً من دون شهادة أو كلمة مرور مضمّنة من البوت السابق.")
            info = [entry for entry in infos if APP_INFO.fullmatch(entry.filename)]
            if len(info) != 1 or info[0].file_size > 1024 * 1024:
                raise BotError("لم يُعثر على Info.plist صالح للتطبيق الرئيسي.")
            metadata = plistlib.loads(ipa.read(info[0]))
        if not isinstance(metadata, dict):
            raise BotError("Info.plist ليس قاموس إعدادات صالحاً.")
        bundle = metadata.get("CFBundleIdentifier")
        version = metadata.get("CFBundleVersion")
        if not isinstance(bundle, str) or not BUNDLE.fullmatch(bundle) or not version:
            raise BotError("معرّف الحزمة أو إصدار التطبيق غير صالح.")
        return {"bundle": bundle, "version": str(version), "expanded_bytes": expanded}
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException) as exc:
        raise BotError("الملف ليس IPA صالحاً.") from exc


def provision_data(path):
    try:
        try:
            result = subprocess.run(
                ["openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", str(path)],
                capture_output=True, timeout=15, check=True,
            )
            content = result.stdout
        except FileNotFoundError:
            wrapper = cms.ContentInfo.load(path.read_bytes(), strict=True)
            if wrapper["content_type"].native != "signed_data":
                raise ValueError
            content = wrapper["content"]["encap_content_info"]["content"].native
        data = plistlib.loads(content)
        if not isinstance(data, dict) or not isinstance(data.get("Entitlements"), dict):
            raise ValueError
        entitlements = data["Entitlements"]
        identifier = entitlements.get("application-identifier")
        if not isinstance(identifier, str) or "." not in identifier:
            raise ValueError
        data["bundle_pattern"] = identifier.split(".", 1)[1]
        return data
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, plistlib.InvalidFileException) as exc:
        raise BotError("ملف mobileprovision غير صالح.") from exc


def profile_supports(profile, bundle):
    pattern = profile["bundle_pattern"]
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        return bundle.startswith(pattern[:-1])
    return pattern == bundle


def sign(source, output, p12, provision, password):
    try:
        binary = SIGNER
        if not os.access(binary, os.X_OK):
            binary = source.parent / "zsign"
            shutil.copyfile(SIGNER, binary)
            binary.chmod(0o700)
        command = [str(binary), "-k", str(p12), "-m", str(provision), "-p", password,
                   "-z", "1", "-o", str(output), str(source)]
        result = subprocess.run(command, cwd=source.parent, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=120, check=False)
    except subprocess.TimeoutExpired as exc:
        raise BotError("انتهت مهلة توقيع هذا التطبيق.") from exc
    except OSError as exc:
        raise BotError("ملف zsign غير متاح لبيئة التشغيل.") from exc
    if result.returncode or not output.is_file():
        raise BotError("فشل التوقيع. راجع الشهادة وكلمة المرور وتوافق البروفايل.")
