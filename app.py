from flask import Flask, render_template_string, request
import cv2
import numpy as np
from PIL import Image
import requests
import io

app = Flask(__name__)

# مفتاح الـ API الخاص بك
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
            <h1 class="text-2xl">QR Safe Scanner</h1>
            <p class="text-blue-100 text-xs mt-1">فحص أمني متقدم عبر VirusTotal</p>
        </div>
        <div class="p-8">
            {% if not result %}
            <form action="/scan" method="post" enctype="multipart/form-data">
                <label class="block p-10 border-2 border-dashed border-blue-100 rounded-3xl cursor-pointer hover:bg-blue-50 transition-all">
                    <span class="text-blue-600 font-bold block mb-2">اضغط لرفع صورة QR</span>
                    <input type="file" name="file" class="hidden" onchange="this.form.submit()">
                </label>
            </form>
            {% elif result == 'safe' %}
                <div class="text-green-500 text-6xl mb-4">✅</div>
                <h2 class="font-bold text-slate-800 text-xl">الرابط آمن</h2>
                <div class="my-4 p-3 bg-slate-50 rounded-xl text-xs break-all">{{ content }}</div>
            {% elif result == 'danger' %}
                <div class="text-red-500 text-6xl mb-4">⚠️</div>
                <h2 class="font-bold text-red-600 text-xl">رابط خطير!</h2>
                <div class="my-4 p-3 bg-red-50 rounded-xl text-xs break-all text-red-700 font-mono">{{ content }}</div>
                <div class="bg-red-600 text-white p-2 rounded-lg font-bold text-sm">اكتشفه {{ count }} محرك أمني!</div>
            {% elif result == 'error' %}
                <div class="text-orange-500 text-6xl mb-4">❌</div>
                <h2 class="font-bold text-slate-800 text-xl">حدث خطأ</h2>
                <p class="text-sm text-slate-500 mt-2">{{ content }}</p>
            {% endif %}
            {% if result %}<a href="/" class="block mt-6 text-indigo-600 font-bold underline text-sm italic">فحص كود جديد ←</a>{% endif %}
        </div>
    </div>
</body>
</html>
"""

def check_vt(url):
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
        if response.status_code == 200:
            aid = response.json()['data']['id']
            res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=headers).json()
            stats = res['data']['attributes']['stats']
            return stats['malicious'] > 0, stats['malicious']
    except: pass
    return False, 0

@app.route('/')
def home():
    return render_template_string(HTML_UI, result=None)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files.get('file')
    if not file: return render_template_string(HTML_UI, result='error', content="لم يتم اختيار ملف")
    
    # قراءة الصورة باستخدام OpenCV
    in_memory_file = io.BytesIO()
    file.save(in_memory_file)
    data = np.frombuffer(in_memory_file.getvalue(), dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    
    # محاولة قراءة الـ QR
    detector = cv2.QRCodeDetector()
    content, points, _ = detector.detectAndDecode(img)
    
    if not content:
        return render_template_string(HTML_UI, result='error', content="لم نتمكن من العثور على رمز QR واضح")

    if content.lower().startswith('http'):
        is_bad, count = check_vt(content)
        return render_template_string(HTML_UI, result='danger' if is_bad else 'safe', content=content, count=count)
    
    return render_template_string(HTML_UI, result='safe', content=f"نص: {content}")

if __name__ == '__main__':
    app.run()
