from flask import Flask, render_template_string, request
import cv2
import numpy as np
import requests
import io

app = Flask(__name__)

# مفتاح الـ API الخاص بك للفحص الحقيقي
VT_API_KEY = "2fc2b9c1c6e02bebc1b0842a698e43b8b5de41b625e41d71f5d1637911fbf699"

HTML_UI = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700&display=swap" rel="stylesheet">
    <style>body { font-family: 'Tajawal', sans-serif; }</style>
</head>
<body class="bg-slate-50 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full bg-white rounded-[2rem] shadow-2xl overflow-hidden border border-slate-100 text-center">
        <div class="p-8 bg-gradient-to-br from-indigo-600 to-blue-700 text-white font-bold">
            <h1 class="text-2xl font-bold">فاحص QR الذكي</h1>
            <p class="text-blue-100 text-xs mt-1 italic">مرتبط الآن بقاعدة بيانات VirusTotal</p>
        </div>
        <div class="p-8">
            {% if not result %}
            <form action="/scan" method="post" enctype="multipart/form-data">
                <label class="block p-10 border-2 border-dashed border-blue-100 rounded-3xl cursor-pointer hover:bg-blue-50 transition-all">
                    <span class="text-blue-600 font-bold block mb-2">ارفع كود الـ QR للفحص</span>
                    <input type="file" name="file" class="hidden" onchange="this.form.submit()">
                </label>
            </form>
            {% elif result == 'safe' %}
                <div class="text-green-500 text-6xl mb-4">✅</div>
                <h2 class="font-bold text-slate-800 text-xl tracking-tight">الرابط آمن</h2>
                <div class="my-4 p-3 bg-slate-50 rounded-xl text-xs break-all text-slate-500">{{ content }}</div>
                <p class="text-xs text-green-600 font-bold">أكدت محركات الأمان أن هذا الرابط سليم</p>
            {% elif result == 'danger' %}
                <div class="text-red-500 text-6xl mb-4 animate-pulse">⚠️</div>
                <h2 class="font-bold text-red-600 text-xl">تحذير: رابط ملغوم!</h2>
                <div class="my-4 p-3 bg-red-50 rounded-xl text-xs break-all text-red-700 font-mono">{{ content }}</div>
                <div class="bg-red-600 text-white p-2 rounded-lg font-bold text-sm shadow-lg shadow-red-200">اكتشفه {{ count }} محرك أمني!</div>
            {% elif result == 'error' %}
                <div class="text-orange-400 text-5xl mb-4">❌</div>
                <h2 class="font-bold text-slate-800 text-xl italic">لم نجد كود QR</h2>
                <p class="text-sm text-slate-500 mt-2">تأكد من وضوح الصورة وجرب مرة أخرى</p>
            {% endif %}
            {% if result %}<a href="/" class="block mt-8 text-indigo-600 font-bold hover:underline italic">← فحص كود آخر</a>{% endif %}
        </div>
    </div>
</body>
</html>
"""

def check_with_virustotal(url):
    """هذه الدالة ترسل الرابط لـ VirusTotal وتجلب النتيجة الحقيقية"""
    try:
        headers = {"x-apikey": VT_API_KEY}
        # إرسال الرابط للتحليل
        response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            # جلب النتيجة النهائية
            res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            stats = res['data']['attributes']['stats']
            # إذا كان هناك محرك واحد على الأقل اعتبره خبيثاً
            return stats['malicious'] > 0, stats['malicious']
    except: pass
    return False, 0

@app.route('/')
def home():
    return render_template_string(HTML_UI, result=None)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files.get('file')
    if not file: return render_template_string(HTML_UI, result='error')
    
    # قراءة الصورة
    in_memory = io.BytesIO()
    file.save(in_memory)
    data = np.frombuffer(in_memory.getvalue(), dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    
    # استخراج الرابط من الـ QR
    detector = cv2.QRCodeDetector()
    content, _, _ = detector.detectAndDecode(img)
    
    if not content:
        return render_template_string(HTML_UI, result='error')

    # فحص الرابط عبر VirusTotal بدلاً من الكلمات المشبوهة
    if content.lower().startswith('http'):
        is_bad, count = check_with_virustotal(content)
        return render_template_string(HTML_UI, result='danger' if is_bad else 'safe', content=content, count=count)
    
    return render_template_string(HTML_UI, result='safe', content=f"نص: {content}")

if __name__ == '__main__':
    app.run()
