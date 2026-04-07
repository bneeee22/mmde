from flask import Flask, render_template_string, request
import cv2
import numpy as np
import requests
import io

app = Flask(__name__)

# مفتاح الـ API الخاص بك
VT_API_KEY = "2fc2b9c1c6e02bebc1b0842a698e43b8b5de41b625e41d71f5d1637911fbf699"

# الواجهة الجديدة: احترافية، عصرية، وبسيطة (Minimalist)
HTML_UI = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QR Code Scan - فحص سريع وآمن</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Tajawal', sans-serif; }
        
        /* تأثيرات حركية ناعمة */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .animate-fadeInUp {
            animation: fadeInUp 0.5s ease-out forwards;
        }

        /* تأثير تحميل ناعم */
        .loader {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3b82f6;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body class="bg-[#F8FAFC] text-slate-800 min-h-screen flex items-center justify-center p-4 antialiased">

    <div class="max-w-xl w-full mx-auto animate-fadeInUp">
        
        <div class="bg-white rounded-[2rem] shadow-[0_20px_50px_rgba(0,0,0,0.05)] border border-slate-100 overflow-hidden relative">
            
            <div class="p-8 text-center bg-white border-b border-slate-100">
                <div class="bg-blue-50 w-20 h-20 rounded-3xl flex items-center justify-center mx-auto mb-5 shadow-inner">
                    <svg class="w-10 h-10 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v1m0 11v1m5-10v1m-10 0v1m10 5v1m-10 0v1m-2-4h14M5 8h14m-14 4h14m-14 4h14"></path></svg>
                </div>
                <h1 class="text-3xl font-extrabold text-slate-950 tracking-tight">QR Code Scan</h1>
                <p class="text-slate-500 mt-2 text-sm font-medium">افحص أي كود QR بسرعة وسهولة تامة</p>
            </div>

            <div class="p-8 md:p-12">
                
                {% if not result %}
                <form id="scanForm" action="/scan" method="post" enctype="multipart/form-data" class="space-y-6">
                    <div class="relative group">
                        <label class="flex flex-col items-center justify-center p-10 bg-slate-50 text-blue-600 rounded-3xl border-2 border-dashed border-blue-100 cursor-pointer hover:bg-blue-50 hover:border-blue-300 transition-all duration-300 transform group-hover:-translate-y-1">
                            <div class="loader-container hidden mb-4">
                                <div class="loader"></div>
                            </div>
                            <svg class="w-12 h-12 mb-4 text-blue-400 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                            <span class="text-base font-bold text-slate-700">اضغط لرفع صورة الكود</span>
                            <p class="text-xs text-slate-400 mt-2 italic">سيتم الفحص تلقائياً فورياً</p>
                            <input type="file" name="file" class="hidden" required onchange="showLoaderAndSubmit(this)">
                        </label>
                    </div>
                </form>

                {% elif result == 'safe' %}
                <div class="text-center">
                    <div class="w-24 h-24 bg-green-50 text-green-500 rounded-full flex items-center justify-center mx-auto mb-6 italic text-5xl shadow-inner shadow-green-100">✓</div>
                    <h2 class="text-2xl font-extrabold text-green-700 tracking-tight">الرمز آمن</h2>
                    <div class="my-6 p-5 bg-slate-50 rounded-2xl border border-slate-100 text-right leading-relaxed">
                        <p class="text-xs text-slate-400 mb-2 font-medium">محتوى الكود المفحوص:</p>
                        <p class="text-slate-600 break-all text-sm leading-relaxed">{{ content }}</p>
                    </div>
                    <p class="text-sm text-green-600 font-bold">تم تأكيد سلامة الرمز ولا توجد تهديدات معروفة</p>
                </div>

                {% elif result == 'danger' %}
                <div class="text-center">
                    <div class="w-24 h-24 bg-red-50 text-red-500 rounded-full flex items-center justify-center mx-auto mb-6 italic text-5xl animate-pulse shadow-inner shadow-red-100">⚠️</div>
                    <h2 class="text-2xl font-extrabold text-red-600 tracking-tight">تحذير: الرمز خطير!</h2>
                    <div class="my-6 p-5 bg-red-50 rounded-2xl border border-red-100 text-right leading-relaxed text-red-700">
                        <p class="text-red-700 break-all text-sm italic">{{ content }}</p>
                    </div>
                    <div class="bg-red-600 text-white p-3 px-6 rounded-2xl inline-block font-extrabold text-sm shadow-lg shadow-red-200">
                        اكتشفه {{ count }} محرك أمني!
                    </div>

                {% elif result == 'error' %}
                <div class="text-center">
                    <div class="w-20 h-20 bg-orange-50 text-orange-400 rounded-full flex items-center justify-center mx-auto mb-6 italic text-3xl">!</div>
                    <h2 class="text-xl font-bold text-slate-800">لم نجد كود QR</h2>
                    <p class="text-sm text-slate-500 mt-2">تأكد من وضوح الصورة وجرب مرة أخرى</p>
                </div>
                {% endif %}

                {% if result %}
                <div class="mt-12 pt-8 border-t border-slate-100 text-center">
                    <a href="/" class="inline-flex items-center text-blue-600 font-bold hover:text-blue-800 transition-colors group">
                        <svg class="w-4 h-4 ml-2 group-hover:-translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 12H5m7 7l-7-7 7-7"></path></svg>
                        فحص كود آخر
                    </a>
                </div>
                {% endif %}
            </div>
        </div>

        <div class="mt-10 text-center text-slate-400 text-xs">
            &copy; 2026 QR Code Scan - جميع الحقوق محفوظة
        </div>
    </div>

    <script>
        function showLoaderAndSubmit(input) {
            if (input.files && input.files[0]) {
                const label = input.closest('label');
                const svg = label.querySelector('svg');
                const text = label.querySelector('span');
                const p = label.querySelector('p');
                const loader = label.querySelector('.loader-container');

                // إظهار اللودر وإخفاء العناصر الأخرى بنعومة
                svg.classList.add('hidden');
                text.classList.add('hidden');
                p.classList.add('hidden');
                loader.classList.remove('hidden');

                setTimeout(() => {
                    input.form.submit();
                }, 100);
            }
        }
    </style>
</body>
</html>
"""

def check_with_virustotal(url):
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
    
    # محاولة قراءة الـ QR
    detector = cv2.QRCodeDetector()
    content, _, _ = detector.detectAndDecode(img)
    
    if not content:
        return render_template_string(HTML_UI, result='error')

    if content.lower().startswith('http'):
        is_bad, count = check_with_virustotal(content)
        return render_template_string(HTML_UI, result='danger' if is_bad else 'safe', content=content, count=count)
    
    return render_template_string(HTML_UI, result='safe', content=f"نص: {content}")

if __name__ == '__main__':
    app.run()
