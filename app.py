from flask import Flask, render_template, request
import cv2
import numpy as np
import requests
import io

app = Flask(__name__)

# مفتاح الـ API الخاص بك للفحص العالمي
VT_API_KEY = "2fc2b9c1c6e02bebc1b0842a698e43b8b5de41b625e41d71f5d1637911fbf699"

def check_with_virustotal(url):
    """دالة الاتصال بـ VirusTotal للحصول على نتيجة الفحص الحقيقية"""
    try:
        headers = {"x-apikey": VT_API_KEY}
        # خطوة 1: إرسال الرابط
        response = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            # خطوة 2: جلب تحليل المحركات الأمنية
            res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            stats = res['data']['attributes']['stats']
            return stats['malicious'] > 0, stats['malicious']
    except:
        pass
    return False, 0

@app.route('/')
def home():
    return render_template('index.html', result=None)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files.get('file')
    if not file: 
        return render_template('index.html', result='error')
    
    try:
        # قراءة الصورة وتحويلها لمصفوفة يفهمها OpenCV
        in_memory = io.BytesIO()
        file.save(in_memory)
        data = np.frombuffer(in_memory.getvalue(), dtype=np.uint8)
        img = cv2.imdecode(data, cv2.IMREAD_COLOR)
        
        # قراءة كود الـ QR
        detector = cv2.QRCodeDetector()
        content, _, _ = detector.detectAndDecode(img)
        
        if not content:
            return render_template('index.html', result='error')

        # إذا كان المحتوى يبدأ بـ http فهو رابط ويحتاج فحص
        if content.lower().startswith('http'):
            is_bad, count = check_with_virustotal(content)
            return render_template('index.html', result='danger' if is_bad else 'safe', content=content, count=count)
        
        # إذا كان نصاً عادياً
        return render_template('index.html', result='safe', content=f"نص: {content}")
    except:
        return render_template('index.html', result='error')

if __name__ == '__main__':
    app.run()
