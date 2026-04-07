from flask import Flask, render_template_string, request
from pyzbar.pyzbar import decode
from PIL import Image
import requests

app = Flask(__name__)

# مفتاحك الخاص
VT_API_KEY = "2fc2b9c1c6e02bebc1b0842a698e43b8b5de41b625e41d71f5d1637911fbf699"

# واجهة الموقع بتصميم Tailwind الحديث (مدمجة لضمان التحديث)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700&display=swap" rel="stylesheet">
    <style>body { font-family: 'Tajawal', sans-serif; }</style>
</head>
<body class="bg-slate-50 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full bg-white rounded-[2.5rem] shadow-2xl overflow-hidden border border-slate-100">
        <div class="p-8 text-center bg-gradient-to-br from-blue-600 to-indigo-700 text-white">
            <h1 class="text-2xl font-bold">QR Safe Scanner</h1>
            <p class="text-blue-100 text-sm mt-1 font-bold">مدعوم بـ VirusTotal</p>
        </div>
        <div class="p-8 text-center">
            {% if not result %}
            <form action="/scan" method="post" enctype="multipart/form-data" class="space-y-4">
                <label class="block p-6 border-2 border-dashed border-blue-200 rounded-2xl cursor-pointer hover:bg-blue-50">
                    <span class="text-blue-600 font-bold">اختر صورة QR للفحص</span>
                    <input type="file" name="file" class="hidden" onchange="this.form.submit()">
                </label>
            </form>
            {% elif result == 'safe' %}
                <div class="text-green-500 text-5xl mb-2">✅</div>
                <h2 class="text-xl font-bold">الرابط آمن</h2>
                <p class="text-xs bg-slate-50 p-2 mt-2 rounded break-all">{{ content }}</p>
            {% elif result == 'danger' %}
                <div class="text-red-500 text-5xl mb-2">⚠️</div>
                <h2 class="text-xl font-bold text-red-600">رابط خطير!</h2>
                <p class="text-xs bg-red-50 p-2 mt-2 rounded break-all text-red-700">{{ content }}</p>
                <div class="mt-2 bg-red-600 text-white p-1 rounded font-bold text-sm underline">اكتشفه {{ count }} محرك أمني</div>
            {% endif %}
            {% if result %} <a href="/" class="block mt-6 text-blue-600 font-bold underline text-sm">فحص صورة أخرى</a> {% endif %}
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
            analysis_id = response.json()['data']['id']
            res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            stats = res['data']['attributes']['stats']
            return stats['malicious'] > 0, stats['malicious']
    except: pass
    return False, 0

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, result=None)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files.get('file')
    if not file: return "خطأ في الملف"
    img = Image.open(file)
    decoded = decode(img)
    if not decoded: return "لم يتم العثور على كود"
    
    content = decoded[0].data.decode('utf-8')
    if content.startswith('http'):
        is_bad, count = check_vt(content)
        return render_template_string(HTML_TEMPLATE, result='danger' if is_bad else 'safe', content=content, count=count)
    return render_template_string(HTML_TEMPLATE, result='safe', content=f"نص: {content}")

if __name__ == '__main__':
    app.run()
