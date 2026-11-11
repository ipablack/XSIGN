from html import escape
from string import Template
from urllib.parse import quote

from xsignbot.core import origin

INSTALL_STYLE = """
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif;
      background: radial-gradient(circle at 50% 0%, #0f2447 0%, #06080d 65%, #030407 100%);
      color: #ffffff;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .glass-card {
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
    }
    .logo-box {
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
    }
    .title {
      font-size: 23px;
      font-weight: 800;
      background: linear-gradient(90deg, #fff, #d4af37);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 6px;
    }
    .subtitle {
      font-size: 13px;
      color: #94a3b8;
      margin-bottom: 20px;
    }
    .info-box {
      background: rgba(6, 10, 18, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.07);
      border-radius: 16px;
      padding: 14px;
      margin-bottom: 24px;
      text-align: right;
      font-size: 13px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .info-row:last-child { border-bottom: none; }
    .label { color: #64748b; font-weight: 600; }
    .val { color: #e2e8f0; font-weight: 600; direction: ltr; max-width: 65%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .btn-install {
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
    }
    .btn-install:active { transform: scale(0.97); }
    .hint {
      font-size: 11.5px;
      color: #64748b;
      margin-top: 14px;
    }
"""

INSTALL = Template("""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>$name | التثبيت</title>
<style>
$css
.logo-img {width:100%;height:100%;object-fit:cover;border-radius:27px}
.title {overflow-wrap:anywhere}
</style>
</head>
<body>
<div class="glass-card">
  <div class="logo-box"><img class="logo-img" src="$image" alt=""></div>
  <div class="title">$name</div>
  <div class="subtitle">التطبيق جاهز للتثبيت</div>
  <div class="info-box">
    <div class="info-row"><span class="label">الشهادة</span><span class="val">$team</span></div>
    <div class="info-row"><span class="label">انتهاء البروفايل</span><span class="val">$expiry</span></div>
    <div class="info-row"><span class="label">الإصدار</span><span class="val">$version</span></div>
  </div>
  <a class="btn-install" href="$install">تثبيت $name</a>
  <p class="hint">إذا فتحت الصفحة داخل تيليغرام، افتحها في Safari واضغط تثبيت.</p>
</div>
</body>
</html>""")


def install_page(record, token):
    app = record["app"]
    safe = lambda value: escape(str(value), quote=True)
    query = quote(token, safe="")
    manifest = f"{origin()}/api/plist?token={query}"
    install = "itms-services://?action=download-manifest&url=" + quote(manifest, safe="")
    return INSTALL.substitute(
        css=INSTALL_STYLE, name=safe(app["name"]),
        image=safe(f"/api/install-image?token={query}"),
        team=safe(record["team"]), expiry=safe(record["expiry"]),
        version=safe(app["version"]), install=safe(install),
    )


UPLOAD_PAGE = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSign | رفع IPA</title>
<style>
body{margin:0;background:#080b12;color:#f4f6fb;font:17px system-ui,sans-serif;display:grid;min-height:100vh;place-items:center}
main{box-sizing:border-box;width:min(92vw,460px);background:#111725;padding:24px;border:1px solid #2b3448;border-radius:20px}
input,button{font:inherit;max-width:100%}button{display:block;margin-top:20px;background:#1377fb;color:#fff;border:0;border-radius:10px;padding:12px 20px}
button:disabled{opacity:.55}p{line-height:1.55}h1{font-size:24px;margin-top:0}
</style>
</head>
<body><main>
<h1>رفع IPA إلى XSign</h1>
<form id="upload">
  <label for="ipa">اختر ملف IPA حتى 250 MiB</label>
  <p><input id="ipa" type="file" accept=".ipa,application/octet-stream" required></p>
  <button id="submit">رفع الملف</button>
</form>
<p id="state" role="status" aria-live="polite"></p>
</main>
<script>
const form = document.querySelector('#upload');
const submit = document.querySelector('#submit');
const statusText = document.querySelector('#state');
const ticket = new URLSearchParams(location.hash.slice(1)).get('t');
if (!ticket) {
  submit.disabled = true;
  statusText.textContent = 'افتح رابط الرفع من لوحة الأدمن في تيليغرام.';
}
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = document.querySelector('#ipa').files[0];
  if (!file || !file.name.toLowerCase().endsWith('.ipa') || file.size < 1 || file.size > 250 * 1024 * 1024) {
    statusText.textContent = 'اختر IPA صالحاً لا يتجاوز 250 MiB.';
    return;
  }
  submit.disabled = true;
  statusText.textContent = 'جارٍ رفع الملف. أبقِ الصفحة مفتوحة.';
  try {
    const upload = await fetch('/api/admin/upload/file', {
      method: 'PUT', credentials: 'omit', redirect: 'error',
      headers: {'Content-Type': 'application/octet-stream', 'X-Upload-Ticket': ticket,
                'X-Upload-Size': String(file.size)},
      body: file
    });
    if (!upload.ok) {
      const body = await upload.json().catch(() => ({}));
      throw Error(typeof body.detail === 'string' ? body.detail : 'تعذّر رفع الملف.');
    }
    statusText.textContent = 'تم الرفع. ارجع للبوت وأكمل الاسم والصورة ثم اضغط نشر التطبيق.';
  } catch (error) {
    statusText.textContent = error.message || 'تعذّر الرفع.';
    submit.disabled = false;
  }
});
</script>
</body></html>"""
