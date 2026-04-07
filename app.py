from flask import Flask, render_template, request
from pyzbar.pyzbar import decode
from PIL import Image
import requests

app = Flask(__name__)

# ضع مفتاح الـ API الخاص بك هنا
VT_API_KEY = "2fc2b9c1c6e02bebc1b0842a698e43b8b5de41b625e41d71f5d1637911fbf699ا"

def check_with_virustotal(url):
    """فحص الرابط عبر قاعدة بيانات VirusTotal العالمية"""
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url}
        headers = {"x-apikey": VT_API_KEY}
        
        # إرسال الرابط للفحص
        response = requests.post(vt_url, data=payload, headers=headers)
        if response.status_code == 200:
            # الحصول على نتائج التحليل
            analysis_id = response.json()['data']['id']
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            result = requests.get(analysis_url, headers=headers).json()
            stats = result['data']['attributes']['stats']
            
            # إذا وجد محرك فحص واحد على الأقل أنه ضار
            is_malicious = stats['malicious'] > 0
            return is_malicious, stats['malicious']
    except Exception as e:
        print(f"Error: {e}")
    return False, 0

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return "لم يتم اختيار ملف"
    
    file = request.files['file']
    img = Image.open(file)
    results = decode(img)

    if not results:
        return "<div style='text-align:center; padding:50px;'><h2>❌ لم يتم العثور على رمز QR أو الصورة تالفة</h2><a href='/'>عودة</a></div>"

    content = results[0].data.decode('utf-8')

    # إذا كان المحتوى رابطاً، نفحص بـ VirusTotal
    if content.startswith('http'):
        is_bad, count = check_with_virustotal(content)
        if is_bad:
            return f"""
            <div style='text-align:center; padding:50px; font-family:sans-serif;'>
                <h2 style='color:red;'>⚠️ تحذير: رابط غير آمن!</h2>
                <p>تم اكتشاف هذا الرابط كتهديد من قبل {count} محرك فحص.</p>
                <code style='background:#eee; padding:5px;'>{content}</code>
                <br><br><a href='/'>فحص صورة أخرى</a>
            </div>
            """
        else:
            return f"""
            <div style='text-align:center; padding:50px; font-family:sans-serif;'>
                <h2 style='color:green;'>✅ الرابط يبدو آمناً</h2>
                <p>تم فحص الرابط عبر VirusTotal ولم يتم العثور على تهديدات.</p>
                <code style='background:#eee; padding:5px;'>{content}</code>
                <br><br><a href='/'>فحص صورة أخرى</a>
            </div>
            """
    
    return f"<div style='text-align:center; padding:50px;'><h2>ℹ️ الرمز يحتوي على نص:</h2><p>{content}</p><a href='/'>عودة</a></div>"

if __name__ == '__main__':
    app.run(debug=True)

if __name__ == '__main__':
    app.run()
