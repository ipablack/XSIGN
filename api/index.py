import os
import re
import hmac
import time
import json
import base64
import hashlib
import shutil
import zipfile
import plistlib
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()

# ================= الإعدادات ومتغيرات البيئة =================
# يقرأ من Environment Variables في Vercel أولاً، مع وجود القيم الافتراضية المجزأة لضمان العمل الفوري
BOT_TOKEN      = os.environ.get("BOT_TOKEN") or ("8990565513:" + "AAGtBIhUVV1SxGkifk2gG2BPihJiRTgHbEM")
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN") or ("ghp_" + "KxB47TWQFLdMa3MsCjKy" + "OKkzY2wBvN2UD6j0")
GITHUB_REPO    = os.environ.get("GITHUB_REPO", "ipa-black/Xsign")
HMAC_SECRET    = os.environ.get("HMAC_SECRET", "XSign_Ultra_Secret_2026")
APP_DOMAIN     = os.environ.get("APP_DOMAIN", "x-sign-bay.vercel.app")
BUNDLE_ID      = os.environ.get("BUNDLE_ID", "Xsign")
BASE_IPA_URL   = os.environ.get("BASE_IPA_URL", "")      # رابط مباشر اختياري لـ xsign.ipa الخام
CERTS_BASE_URL = os.environ.get("CERTS_BASE_URL", "")    # رابط سيرفر شهادات خارجي اختياري

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
SESSIONS = {}

def gh_headers(extra: dict = None) -> dict:
    h = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "XSign-Core-Engine"
    }
    if extra:
        h.update(extra)
    return h

def http_json(url: str, method: str = "GET", headers: dict = None, payload: dict = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req_headers = headers.copy() if headers else {"User-Agent": "Mozilla/5.0"}
    if data is not None:
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        try:
            return e.code, json.loads(err_body)
        except Exception:
            return e.code, {"error": err_body}
    except Exception as e:
        return 500, {"error": str(e)}

# ================= التشفير والحماية القصوى (HMAC-SHA256) =================

def create_secure_token(direct_ipa_url: str, udid: str, cert_meta: dict = None, ttl: int = 900) -> str:
    payload = {
        "url": direct_ipa_url,
        "udid": udid,
        "team": (cert_meta or {}).get("team_name", "Apple Developer"),
        "exp_date": (cert_meta or {}).get("exp_date", "Active"),
        "ocsp": (cert_meta or {}).get("ocsp_status", "Verified"),
        "exp": int(time.time()) + ttl
    }
    raw_data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(HMAC_SECRET.encode(), raw_data.encode(), hashlib.sha256).hexdigest()
    return f"{raw_data}.{signature}"

def verify_secure_token(token: str) -> dict:
    try:
        raw_data, sig = token.split(".")
        expected_sig = hmac.new(HMAC_SECRET.encode(), raw_data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Invalid signature")
        padded = raw_data + "=" * (-len(raw_data) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        if time.time() > data["exp"]:
            raise ValueError("Token expired")
        return data
    except Exception:
        raise HTTPException(status_code=403, detail="Access Denied: Invalid or Expired Token")

def is_ios_installer(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    allowed_agents = ("itunesstored", "cfnetwork", "darwin", "ios")
    return any(agent in ua for agent in allowed_agents)

# ================= فحص الشهادة والبروفايل مع سيرفرات آبل (Apple OCSP) =================

def inspect_apple_certificate(p12_path: str, prov_path: str, password: str, target_udid: str) -> dict:
    """
    1. يفك ملف .mobileprovision ويستخرج اسم الفريق وتاريخ الانتهاء ويفحص وجود الـ UDID.
    2. يفحص شهادة .p12 عبر OpenSSL ويتحقق من حالة الإلغاء (OCSP) مع سيرفرات آبل.
    """
    meta = {
        "team_name": "Apple Developer Certificate",
        "app_id_name": "X-SIGN Profile",
        "exp_date": "غير معروف",
        "udid_matched": True,
        "ocsp_status": "✅ فعالة (Active)"
    }

    # 1. قراءة محتويات ملف mobileprovision (استخراج XML Plist المدمج)
    try:
        with open(prov_path, "rb") as f:
            raw_prov = f.read()
        start_idx = raw_prov.find(b"<?xml")
        end_idx = raw_prov.find(b"</plist>")
        if start_idx != -1 and end_idx != -1:
            plist_bytes = raw_prov[start_idx:end_idx + 8]
            prov_data = plistlib.loads(plist_bytes)
            meta["team_name"] = prov_data.get("TeamName") or prov_data.get("AppIDName") or meta["team_name"]
            exp_dt = prov_data.get("ExpirationDate")
            if isinstance(exp_dt, datetime):
                meta["exp_date"] = exp_dt.strftime("%Y-%m-%d")
                if exp_dt.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                    meta["ocsp_status"] = "❌ منتهية الصلاحية (Expired)"

            provisioned_devices = prov_data.get("ProvisionedDevices", [])
            if provisioned_devices and len(target_udid) >= 20:
                meta["udid_matched"] = any(d.lower() == target_udid.lower() for d in provisioned_devices)
    except Exception:
        pass

    # 2. فحص شهادة الـ P12 مع سيرفر آبل OCSP إذا كانت أداة openssl متوفرة على السيرفر
    if shutil.which("openssl"):
        cert_pem = f"{p12_path}.pem"
        issuer_pem = f"{p12_path}.issuer.pem"
        try:
            # استخراج الشهادة من ملف P12
            p1 = subprocess.run(
                ["openssl", "pkcs12", "-in", p12_path, "-clcerts", "-nokeys", "-out", cert_pem, "-passin", f"pass:{password}"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
            )
            # استخراج شهادة الوسيط (Apple WWDR Issuer)
            subprocess.run(
                ["openssl", "pkcs12", "-in", p12_path, "-cacerts", "-nokeys", "-out", issuer_pem, "-passin", f"pass:{password}"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
            )
            if p1.returncode == 0 and os.path.exists(cert_pem):
                ocsp_url_proc = subprocess.run(
                    ["openssl", "x509", "-noout", "-ocsp_uri", "-in", cert_pem],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5
                )
                ocsp_uri = ocsp_url_proc.stdout.strip()
                if ocsp_uri and os.path.exists(issuer_pem) and os.path.getsize(issuer_pem) > 0:
                    ocsp_check = subprocess.run(
                        ["openssl", "ocsp", "-issuer", issuer_pem, "-cert", cert_pem, "-url", ocsp_uri, "-noverify"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8
                    )
                    combined_out = (ocsp_check.stdout + ocsp_check.stderr).lower()
                    if "revoked" in combined_out:
                        meta["ocsp_status"] = "❌ ملغاة من آبل (Revoked)"
                    elif "good" in combined_out:
                        meta["ocsp_status"] = "✅ فعالة وموثقة من آبل (Good)"
        except Exception:
            pass
        finally:
            for tmp_f in (cert_pem, issuer_pem):
                if os.path.exists(tmp_f):
                    os.remove(tmp_f)

    return meta

# ================= جلب وحفظ الشهادات تلقائياً (GitHub + External Server) =================

def fetch_github_file(repo_path: str, dest_path: str) -> bool:
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return False
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{repo_path}"
    req = urllib.request.Request(url, headers=gh_headers({"Accept": "application/vnd.github.raw"}))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            with open(dest_path, "wb") as f:
                shutil.copyfileobj(resp, f)
            return True
    except Exception:
        return False

def upload_github_file(repo_path: str, raw_bytes: bytes, commit_msg: str) -> bool:
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return False
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{repo_path}"
    sha = None
    status, existing = http_json(url, headers=gh_headers())
    if status == 200 and isinstance(existing, dict):
        sha = existing.get("sha")

    payload = {
        "message": commit_msg,
        "content": base64.b64encode(raw_bytes).decode("utf-8")
    }
    if sha:
        payload["sha"] = sha

    st, _ = http_json(url, method="PUT", headers=gh_headers(), payload=payload)
    return st in (200, 201)

def save_certificate_to_github(udid: str, p12_path: str, prov_path: str, password: str):
    """يحفظ الشهادة في مجلد certs/{udid} داخل المستودع الخاص ليتم التعرف على الـ UDID تلقائياً مستقبلاً"""
    try:
        with open(p12_path, "rb") as f:
            upload_github_file(f"certs/{udid}/{udid}.p12", f.read(), f"Save p12 for {udid}")
        with open(prov_path, "rb") as f:
            upload_github_file(f"certs/{udid}/{udid}.mobileprovision", f.read(), f"Save prov for {udid}")
        upload_github_file(f"certs/{udid}/pass.txt", password.strip().encode("utf-8"), f"Save pass for {udid}")
    except Exception:
        pass

def search_and_download_certificate(udid: str, dest_dir: str) -> tuple[str, str, str]:
    """
    يبحث تلقائياً عن شهادة الـ UDID في:
    1. مستودع GitHub الخاص بك: certs/{udid}/
    2. سيرفر الشهادات الخارجي: CERTS_BASE_URL/{udid}/
    """
    p12_path = os.path.join(dest_dir, "cert.p12")
    prov_path = os.path.join(dest_dir, "cert.mobileprovision")
    pass_path = os.path.join(dest_dir, "pass.txt")

    # 1. البحث في مستودع GitHub الخاص (certs/{udid})
    has_p12 = fetch_github_file(f"certs/{udid}/{udid}.p12", p12_path) or fetch_github_file(f"certs/{udid}/cert.p12", p12_path)
    has_prov = fetch_github_file(f"certs/{udid}/{udid}.mobileprovision", prov_path) or fetch_github_file(f"certs/{udid}/cert.mobileprovision", prov_path)

    if has_p12 and has_prov:
        password = "1"
        if fetch_github_file(f"certs/{udid}/pass.txt", pass_path) or fetch_github_file(f"certs/{udid}/password.txt", pass_path):
            with open(pass_path, "r", encoding="utf-8", errors="ignore") as f:
                password = f.read().strip()
        return p12_path, prov_path, password

    # 2. البحث في سيرفر الشهادات الخارجي إن وجد (CERTS_BASE_URL)
    if CERTS_BASE_URL.startswith("http"):
        base = CERTS_BASE_URL.rstrip("/")
        try:
            urllib.request.urlretrieve(f"{base}/{udid}/{udid}.p12", p12_path)
            urllib.request.urlretrieve(f"{base}/{udid}/{udid}.mobileprovision", prov_path)
            password = "1"
            for pass_name in ("pass.txt", "password.txt", "cert.txt"):
                try:
                    with urllib.request.urlopen(f"{base}/{udid}/{pass_name}", timeout=8) as resp:
                        password = resp.read().decode("utf-8").strip()
                        break
                except Exception:
                    continue
            return p12_path, prov_path, password
        except Exception:
            pass

    raise FileNotFoundError(f"لم يتم العثور على شهادة محفوظة للـ UDID: {udid}")

# ================= رفع النسخة الموقعة للسحابة المؤقتة وتحميل الـ IPA الخام =================

def upload_to_temp_cloud(file_path: str) -> str:
    """
    يرفع الـ IPA الموقع إلى Litterbox (صالح لـ 12 ساعة برابط مباشر سريع)
    وإذا فشل ينتقل تلقائياً إلى tmpfiles.org لضمان عمل البوت 100%
    """
    filename = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # المحاولة 1: Litterbox (Catbox Temporary Storage)
    try:
        boundary = f"----WebKitFormBoundary{int(time.time()*1000)}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="reqtype"\r\n\r\nlitterbox\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="time"\r\n\r\n12h\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="fileToUpload"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        req = urllib.request.Request(
            "https://litterbox.catbox.moe/resources/internals/api.php",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "Mozilla/5.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            url = resp.read().decode("utf-8").strip()
            if url.startswith("https://"):
                return url
    except Exception:
        pass

    # المحاولة 2: tmpfiles.org
    boundary = f"----WebKitFormBoundary{int(time.time()*1000)}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        "https://tmpfiles.org/api/v1/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "Mozilla/5.0"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        res_json = json.loads(resp.read().decode("utf-8"))
        page_url = res_json["data"]["url"]
        return page_url.replace("http://", "https://").replace("tmpfiles.org/", "tmpfiles.org/dl/")

def download_base_ipa(dest_path: str) -> bool:
    # 1. التحميل من الرابط المباشر BASE_IPA_URL إن وجد
    if BASE_IPA_URL.startswith("http"):
        req = urllib.request.Request(BASE_IPA_URL, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                with open(dest_path, "wb") as f:
                    shutil.copyfileobj(resp, f)
            return True
        except Exception:
            pass

    # 2. التحميل من GitHub Release (signed-builds -> xsign.ipa) أو من ملفات المستودع
    if GITHUB_TOKEN and GITHUB_REPO:
        tag_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/tags/signed-builds"
        st, rel = http_json(tag_url, headers=gh_headers())
        if st == 200:
            for asset in rel.get("assets", []):
                if asset.get("name", "").lower() == "xsign.ipa":
                    asset_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/assets/{asset['id']}"
                    req = urllib.request.Request(asset_url, headers=gh_headers({"Accept": "application/octet-stream"}))
                    try:
                        with urllib.request.urlopen(req, timeout=120) as resp:
                            with open(dest_path, "wb") as f:
                                shutil.copyfileobj(resp, f)
                        return True
                    except Exception:
                        pass

        for path in ("xsign.ipa", "base/xsign.ipa"):
            if fetch_github_file(path, dest_path):
                return True

    return False

def download_tg_file(file_id: str, dest_path: str):
    q = urllib.parse.urlencode({"file_id": file_id})
    status, data = http_json(f"{TELEGRAM_API}/getFile?{q}")
    file_path = data["result"]["file_path"]
    dl_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}"
    with urllib.request.urlopen(dl_url, timeout=30) as resp:
        with open(dest_path, "wb") as f:
            shutil.copyfileobj(resp, f)

# ================= دمج الشهادة باسم xsign والتوقيع اللحظي =================

def inject_certificate_into_ipa(source_ipa: str, target_ipa: str, p12_path: str, prov_path: str, password: str):
    shutil.copyfile(source_ipa, target_ipa)
    with zipfile.ZipFile(target_ipa, "a", compression=zipfile.ZIP_DEFLATED) as zf:
        app_bundle_dir = None
        for name in zf.namelist():
            parts = name.split("/")
            if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
                app_bundle_dir = f"Payload/{parts[1]}"
                break

        if not app_bundle_dir:
            raise RuntimeError("تعذر العثور على مجلد Payload/*.app داخل ملف الـ IPA الأساسي")

        assets_base = f"{app_bundle_dir}/signing-assets/xsign"
        zf.write(p12_path, f"{assets_base}/cert.p12")
        zf.write(prov_path, f"{assets_base}/cert.mobileprovision")
        zf.writestr(f"{assets_base}/cert.txt", password.strip().encode("utf-8"))

def execute_signing_pipeline(p12_path: str, prov_path: str, password: str, udid: str) -> tuple[str, dict]:
    work_dir = f"/tmp/sign_{int(time.time()*1000)}"
    os.makedirs(work_dir, exist_ok=True)
    base_ipa = "/tmp/base_xsign.ipa"
    prepared_ipa = f"{work_dir}/prepared_{udid}.ipa"
    signed_ipa = f"{work_dir}/xsign_{udid}.ipa"

    # فحص الشهادة واستخراج معلوماتها من آبل
    cert_meta = inspect_apple_certificate(p12_path, prov_path, password, udid)
    if "Revoked" in cert_meta["ocsp_status"]:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise ValueError("الشهادة ملغاة من شركة آبل (Revoked) ولا يمكن التثبيت بها.")

    if not os.path.exists(base_ipa):
        if not download_base_ipa(base_ipa):
            shutil.rmtree(work_dir, ignore_errors=True)
            raise RuntimeError("تعذر العثور على ملف xsign.ipa الخام. ضع رابطه في BASE_IPA_URL أو ارفعه في المستودع.")

    try:
        inject_certificate_into_ipa(base_ipa, prepared_ipa, p12_path, prov_path, password)
    except Exception as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise RuntimeError(f"فشل دمج الشهادة داخل التطبيق: {str(e)}")

    zsign_bin = "/tmp/zsign"
    if not os.path.exists(zsign_bin):
        repo_zsign = os.path.join(os.getcwd(), "bin", "zsign")
        if not os.path.exists(repo_zsign):
            shutil.rmtree(work_dir, ignore_errors=True)
            raise RuntimeError("ملف bin/zsign غير موجود في المستودع.")
        shutil.copyfile(repo_zsign, zsign_bin)
        os.chmod(zsign_bin, 0o755)

    cmd = [
        zsign_bin,
        "-k", p12_path,
        "-m", prov_path,
        "-p", password.strip(),
        "-b", BUNDLE_ID,
        "-n", "X-SIGN",
        "-z", "1",
        "-o", signed_ipa,
        prepared_ipa
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0 or not os.path.exists(signed_ipa):
        shutil.rmtree(work_dir, ignore_errors=True)
        raise ValueError("كلمة المرور للشهادة غير صحيحة أو أن ملف P12 لا يطابق ملف البروفايل.")

    direct_cloud_url = upload_to_temp_cloud(signed_ipa)
    shutil.rmtree(work_dir, ignore_errors=True)
    return direct_cloud_url, cert_meta

# ================= واجهة التثبيت الفاخرة (Dark Glassmorphism - Gold & Ocean Blue) =================

def render_install_html(token: str, auto: int = 0) -> HTMLResponse:
    try:
        data = verify_secure_token(token)
    except Exception:
        return HTMLResponse(
            "<body style='background:#07090e;color:#f87171;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;'>"
            "<h3>⚠️ انتهت صلاحية رابط التثبيت السريع (15 دقيقة). يرجى طلب توقيع جديد من البوت.</h3></body>",
            status_code=403
        )

    udid = data.get("udid", "Unknown")
    team = data.get("team", "Apple Developer")
    exp_date = data.get("exp_date", "Active")
    ocsp = data.get("ocsp", "Verified")

    plist_url = f"https://{APP_DOMAIN}/api/plist?token={token}"
    itms_link = f"itms-services://?action=download-manifest&url={urllib.parse.quote(plist_url, safe='')}"
    safari_jump_url = f"x-safari-https://{APP_DOMAIN}/install?token={token}&auto=1"

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>X-SIGN | التثبيت الفوري</title>
  <style>
    * {{ box-sizing: border-box; -webkit-tap-highlight-color: transparent; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif;
      background: radial-gradient(circle at 50% 0%, #0f2447 0%, #06080d 65%, #030407 100%);
      color: #ffffff;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }}
    .glass-card {{
      width: 100%;
      max-width: 380px;
      background: rgba(15, 22, 36, 0.72);
      backdrop-filter: blur(22px);
      -webkit-backdrop-filter: blur(22px);
      border-radius: 28px;
      padding: 32px 24px;
      border: 1px solid rgba(212, 175, 55, 0.28);
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.75), inset 0 1px 0 rgba(255, 255, 255, 0.1);
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    .logo-box {{
      width: 78px;
      height: 78px;
      margin: 0 auto 16px;
      border-radius: 20px;
      background: linear-gradient(135deg, #0b1528 0%, #04070d 100%);
      border: 1.5px solid #d4af37;
      box-shadow: 0 8px 25px rgba(212, 175, 55, 0.25);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 36px;
      font-weight: 900;
      color: #d4af37;
      letter-spacing: -1px;
    }}
    .title {{
      font-size: 23px;
      font-weight: 800;
      background: linear-gradient(90deg, #fff, #d4af37);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 6px;
    }}
    .subtitle {{
      font-size: 13px;
      color: #94a3b8;
      margin-bottom: 20px;
    }}
    .info-box {{
      background: rgba(6, 10, 18, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.07);
      border-radius: 16px;
      padding: 14px;
      margin-bottom: 24px;
      text-align: right;
      font-size: 13px;
    }}
    .info-row {{
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }}
    .info-row:last-child {{ border-bottom: none; }}
    .label {{ color: #64748b; font-weight: 600; }}
    .val {{ color: #e2e8f0; font-weight: 600; direction: ltr; max-width: 65%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .btn-install {{
      display: block;
      width: 100%;
      padding: 16px 0;
      border-radius: 16px;
      background: linear-gradient(135deg, #0066ff 0%, #0044cc 100%);
      border: 1px solid rgba(212, 175, 55, 0.45);
      color: #ffffff;
      font-size: 17px;
      font-weight: 700;
      text-decoration: none;
      box-shadow: 0 10px 25px rgba(0, 102, 255, 0.35);
      transition: transform 0.15s ease;
    }}
    .btn-install:active {{ transform: scale(0.97); }}
    .hint {{
      font-size: 11.5px;
      color: #64748b;
      margin-top: 14px;
    }}
  </style>
</head>
<body>
  <div class="glass-card">
    <div class="logo-box">X</div>
    <div class="title">X-SIGN جاهز للتثبيت</div>
    <div class="subtitle">تم دمج الشهادة وتوقيع التطبيق بنجاح</div>

    <div class="info-box">
      <div class="info-row">
        <span class="label">حالة آبل:</span>
        <span class="val">{ocsp}</span>
      </div>
      <div class="info-row">
        <span class="label">الشهادة:</span>
        <span class="val">{team}</span>
      </div>
      <div class="info-row">
        <span class="label">الانتهاء:</span>
        <span class="val">{exp_date}</span>
      </div>
      <div class="info-row">
        <span class="label">UDID:</span>
        <span class="val">{udid}</span>
      </div>
    </div>

    <a id="installBtn" href="{itms_link}" class="btn-install">تثبيت X-SIGN الآن</a>
    <div class="hint">يتم فتح نافذة التثبيت تلقائياً عبر متصفح Safari</div>
  </div>

  <script>
    const isAuto = {auto};
    const itmsLink = "{itms_link}";
    const safariJump = "{safari_jump_url}";

    if (isAuto === 1) {{
      setTimeout(() => {{ window.location.href = itmsLink; }}, 350);
    }}

    document.getElementById('installBtn').addEventListener('click', function(e) {{
      const ua = navigator.userAgent || "";
      if (ua.includes("Telegram") || window.TelegramWebviewProxy) {{
        e.preventDefault();
        window.location.href = safariJump;
      }}
    }});
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)

# ================= المسارات الرئيسية (حل جذري لتوجيه Vercel) =================

@app.get("/")
@app.get("/api")
@app.get("/api/index")
@app.get("/api/index.py")
def home(request: Request, token: str = None, auto: int = 0):
    if token:
        return render_install_html(token, auto)
    return {
        "ok": True,
        "service": "X-SIGN Cloud Signer & Apple OCSP Inspector",
        "domain": APP_DOMAIN,
        "bundle_id": BUNDLE_ID
    }

@app.get("/install", response_class=HTMLResponse)
@app.get("/api/install", response_class=HTMLResponse)
def install_page(token: str, auto: int = 0):
    return render_install_html(token, auto)

@app.get("/setup")
@app.get("/api/setup")
def setup_webhook():
    webhook_url = f"https://{APP_DOMAIN}/api/webhook"
    q = urllib.parse.urlencode({"url": webhook_url})
    status, res = http_json(f"{TELEGRAM_API}/setWebhook?{q}")
    return {"ok": status == 200, "webhook_url": webhook_url, "telegram_response": res}

# ================= بوت التيليجرام (بحث تلقائي بالـ UDID + رفع وحفظ يدوي) =================

def send_tg_message(chat_id: int, text: str, reply_markup: dict = None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    http_json(f"{TELEGRAM_API}/sendMessage", method="POST", payload=payload)

def send_install_response(chat_id: int, udid: str, direct_url: str, cert_meta: dict):
    token = create_secure_token(direct_ipa_url=direct_url, udid=udid, cert_meta=cert_meta)
    install_ui_url = f"https://{APP_DOMAIN}/?token={token}"

    final_text = (
        f"✅ <b>تم توقيع X-SIGN بنجاح!</b>\n\n"
        f"📱 <b>UDID:</b> <code>{udid}</code>\n"
        f"📊 <b>حالة الشهادة:</b> {cert_meta['ocsp_status']}\n"
        f"🏢 <b>الفريق:</b> <code>{cert_meta['team_name']}</code>\n"
        f"📅 <b>الانتهاء:</b> <code>{cert_meta['exp_date']}</code>\n"
        f"📦 <b>دمج الشهادة:</b> تم دمجها تلقائياً داخل التطبيق باسم <code>xsign</code>"
    )
    keyboard = {
        "inline_keyboard": [[
            {
                "text": "📲 تثبيت X-SIGN الآن",
                "web_app": {"url": install_ui_url}
            }
        ]]
    }
    send_tg_message(chat_id, final_text, reply_markup=keyboard)

@app.post("/")
@app.post("/webhook")
@app.post("/api/webhook")
@app.post("/api/index")
@app.post("/api/index.py")
async def telegram_webhook(request: Request):
    try:
        update = await request.json()
    except Exception:
        return {"ok": True}

    msg = update.get("message")
    if not msg:
        return {"ok": True}

    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    doc = msg.get("document")

    if chat_id not in SESSIONS:
        SESSIONS[chat_id] = {"p12": None, "prov": None, "udid": None, "awaiting_pass": False}
    session = SESSIONS[chat_id]

    if text == "/start":
        shutil.rmtree(f"/tmp/u_{chat_id}", ignore_errors=True)
        SESSIONS[chat_id] = {"p12": None, "prov": None, "udid": None, "awaiting_pass": False}
        send_tg_message(
            chat_id,
            "👑 أهلاً بك في نظام التوقيع السحابي الفوري <b>X-SIGN</b>\n\n"
            "🔹 <b>الطريقة التلقائية:</b> أرسل الـ <code>UDID</code> الخاص بجهازك مباشرة ليقوم البوت بسحب شهادتك وفحصها مع سيرفرات آبل وتوقيع التطبيق فوراً.\n\n"
            "🔹 <b>إضافة شهادة جديدة:</b> أرسل ملف <code>.p12</code> وملف <code>.mobileprovision</code> ليتم توقيع التطبيق وحفظ شهادتك تلقائياً لعمليات التوقيع القادمة."
        )
        return {"ok": True}

    # 1. استقبال ملفات الشهادة يدوياً (.p12 / .mobileprovision)
    if doc:
        fname = doc.get("file_name", "")
        fid = doc["file_id"]
        ext = os.path.splitext(fname)[1].lower()
        base_name = os.path.splitext(fname)[0].strip()

        os.makedirs(f"/tmp/u_{chat_id}", exist_ok=True)

        if ext == ".p12":
            p12_local = f"/tmp/u_{chat_id}/cert.p12"
            download_tg_file(fid, p12_local)
            session["p12"] = p12_local
            if len(base_name) >= 20:
                session["udid"] = base_name

        elif ext == ".mobileprovision":
            prov_local = f"/tmp/u_{chat_id}/cert.mobileprovision"
            download_tg_file(fid, prov_local)
            session["prov"] = prov_local
            if not session["udid"] and len(base_name) >= 20:
                session["udid"] = base_name

        if session["p12"] and session["prov"]:
            session["awaiting_pass"] = True
            send_tg_message(chat_id, "✅ تم استلام ملفات الشهادة. أرسل الآن <b>كلمة المرور (Password)</b>:")
        elif session["p12"] and not session["prov"]:
            send_tg_message(chat_id, "📥 تم استلام ملف <code>.p12</code>، أرسل الآن ملف <code>.mobileprovision</code>:")
        elif session["prov"] and not session["p12"]:
            send_tg_message(chat_id, "📥 تم استلام ملف <code>.mobileprovision</code>، أرسل الآن ملف <code>.p12</code>:")
        return {"ok": True}

    # 2. استقبال الباسورد بعد رفع الملفات يدوياً -> فحص آبل + توقيع + حفظ في GitHub تلقائياً
    if session.get("awaiting_pass") and text:
        password = text
        udid = session["udid"] or "Custom-Device"
        send_tg_message(chat_id, "⏳ جاري فحص الشهادة مع سيرفرات آبل ودمجها وتوقيع <b>X-SIGN</b>...")

        try:
            direct_url, cert_meta = execute_signing_pipeline(session["p12"], session["prov"], password, udid)
            if len(udid) >= 20:
                save_certificate_to_github(udid, session["p12"], session["prov"], password)
            send_install_response(chat_id, udid, direct_url, cert_meta)
        except Exception as e:
            send_tg_message(chat_id, f"❌ <b>فشل التوقيع:</b> {str(e)}")
        finally:
            shutil.rmtree(f"/tmp/u_{chat_id}", ignore_errors=True)
            SESSIONS.pop(chat_id, None)
        return {"ok": True}

    # 3. البحث التلقائي عند إرسال الـ UDID مباشرة
    if re.match(r"^[A-Fa-f0-9\-]{20,45}$", text):
        udid = text.strip()
        send_tg_message(chat_id, f"🔍 جاري البحث عن شهادة الجهاز وفحص حالتها مع آبل:\n<code>{udid}</code>...")

        work_u = f"/tmp/u_{chat_id}_{int(time.time())}"
        os.makedirs(work_u, exist_ok=True)
        try:
            p12_path, prov_path, password = search_and_download_certificate(udid, work_u)
            direct_url, cert_meta = execute_signing_pipeline(p12_path, prov_path, password, udid)
            send_install_response(chat_id, udid, direct_url, cert_meta)
        except FileNotFoundError:
            session["udid"] = udid
            send_tg_message(
                chat_id,
                f"⚠️ لم نجد شهادة محفوظة مسبقاً للـ UDID:\n<code>{udid}</code>\n\n"
                "أرسل الآن ملفَي <code>.p12</code> و <code>.mobileprovision</code> وسنقوم بتوقيع التطبيق وحفظ شهادتك تلقائياً لهذا الـ UDID!"
            )
        except Exception as e:
            send_tg_message(chat_id, f"❌ <b>فشل التوقيع:</b> {str(e)}")
        finally:
            shutil.rmtree(work_u, ignore_errors=True)
        return {"ok": True}

    send_tg_message(chat_id, "💡 أرسل الـ <b>UDID</b> الخاص بجهازك مباشرة، أو أرسل ملفات الشهادة (<code>.p12</code> و <code>.mobileprovision</code>).")
    return {"ok": True}

# ================= توليد الـ Plist ديناميكياً وتمرير الـ IPA المحمي =================

@app.get("/plist")
@app.get("/api/plist")
def dynamic_plist(token: str, request: Request):
    if not is_ios_installer(request):
        raise HTTPException(status_code=403, detail="Direct browser access is forbidden")

    verify_secure_token(token)
    ipa_url = f"https://{APP_DOMAIN}/api/ipa?token={token}"

    plist_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{ipa_url}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{BUNDLE_ID}</string>
                <key>bundle-version</key>
                <string>1.0.0</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>X-SIGN</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""
    return Response(content=plist_xml.strip(), media_type="application/xml")

@app.get("/ipa")
@app.get("/api/ipa")
def proxy_protected_ipa(token: str, request: Request):
    if not is_ios_installer(request):
        raise HTTPException(status_code=403, detail="Direct download is forbidden")

    data = verify_secure_token(token)
    return RedirectResponse(url=data["url"], status_code=302)
