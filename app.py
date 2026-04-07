from flask import Flask, render_template, request
from pyzbar.pyzbar import decode
from PIL import Image
import requests

app = Flask(__name__)

# مفتاح الـ API الخاص بك الذي زودتني به
VT_API_KEY = "2fc2b9c1c6e02bebc1b0842a698e43b8b5de41b625e41d71f5d1637911fbf699"

def check_with_virustotal(url):
    """إرسال الرابط إلى VirusTotal للفحص الأمني"""
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url}
        headers = {"x-apikey": VT_API_KEY}
        
        # طلب فحص الرابط
        response = requests.post(vt_url, data=payload, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            # جلب النتيجة النهائية بعد التحليل
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            result = requests.get(analysis_url, headers=headers).json()
            stats = result['data']['attributes']['stats']
            
            # malicious يعني عدد المحركات التي صنفته كفيروس أو خطر
            return stats['malicious'] > 0, stats['malicious']
    except Exception as e:
        print(f"خطأ في الاتصال بـ VirusTotal: {e}")
    return False, 0

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return "برجاء رفع صورة QR"
    
    file = request.files['file']
    if file.filename == '':
        return "لم يتم اختيار ملف"

    img = Image.open(file)
    results = decode(img)

    if not results:
        return render_template('result.html', status="error", message="عذراً، لم نكتشف أي رمز QR في هذه الصورة.")

    content = results[0].data.decode('utf-8')

    # فحص إذا كان المحتوى يبدأ بـ http (رابط)
    if content.lower().startswith('http'):
        is_malicious, count = check_with_virustotal(content)
        if is_malicious:
            return render_template('result.html', status="danger", url=content, count=count)
        else:
            return render_template('result.html', status="safe", url=content)
    
    # إذا كان الـ QR يحتوي على نص فقط وليس رابط
    return render_template('result.html', status="info", text=content)

if __name__ == '__main__':
    app.run(debug=True)
