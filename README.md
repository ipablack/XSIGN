# XSign Bot على Kerit Cloud Free

GitHub يحفظ الكود والـIPA والصور في مستودع خاص. Kerit Cloud يشغّل البوت والتوقيع وصفحات التثبيت. تُحفظ حالة البوت في SQLite داخل مساحة الخدمة الدائمة.

## التشغيل

1. ارفع محتويات الحزمة إلى جذر مستودع GitHub خاص. أنشئ فيه مسودة Release بوسم `xsign-bot-assets` عبر **Releases → Draft a new release → Save draft**. إذا عندك مسودة بنفس الوسم، استخدمها.
2. في [Kerit Cloud](https://kerit.cloud/free-telegram-bot-hosting/) اختر **Free** مع **Python 3.12**، واربط مستودع GitHub عبر Git Deploy. ثبّت الحزم من `requirements.txt` في إعداد تثبيت حزم Python. اضبط أمر التشغيل على `python main.py`.
3. خذ عنوان HTTPS العام لخدمتك. اضبط المتغيرات التالية في لوحة الاستضافة، ثم شغّل البوت.

| المتغير | القيمة |
| --- | --- |
| `APP_DOMAIN` | رابط HTTPS العام دون مسار |
| `BOT_TOKEN` | توكن BotFather. استخدم التوكن القديم للاحتفاظ بنفس البوت |
| `ADMIN_ID` | رقم حساب أدمن تلغرام |
| `GITHUB_REPOSITORY` | اسم المستودع الخاص بصيغة `OWNER/REPO` |
| `GITHUB_TOKEN` | Fine-grained token للمستودع وحده بصلاحية Contents Read and write |

يقرأ البوت منفذ `PORT` أو `SERVER_PORT`. إذا أعطتك اللوحة منفذاً عاماً يوجّه إلى منفذ داخلي مختلف، اضبط `PORT` على المنفذ الداخلي المخصص للخدمة. القيمة الافتراضية 8080. تبقى قاعدة البيانات في `~/.xsign` ويمكن اختيار مجلد دائم آخر عبر `XSIGN_DATA_DIR`.

عند ظهور `XSign webhook connected to Telegram.` في سجل التشغيل، أرسل `/start`. يسجّل البوت تلقائياً عنوان `/api/webhook`. أرسل `/admin` لإضافة التطبيقات والصور، ثم جرّب توقيع تطبيق واحد أولاً.

خطة Free تعطي 256 MB ذاكرة و2 GB مساحة دائمة حسب Kerit Cloud. تعمل دفعات التوقيع بعملية واحدة في كل مرة. الحزم الكبيرة تعتمد على حجمها بعد الفك والذاكرة المتاحة. محرك zsign المرفق Linux x86-64 ويحتاج مكتبة `libcrypto.so.3` في بيئة التشغيل. رخصته في `licenses/zsign-LICENSE.txt`.
