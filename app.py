from flask import Flask, render_template, request
from PIL import Image
import re
import cv2
import numpy as np

app = Flask(__name__)

# فحص بسيط للرابط
def is_suspicious(url):
    suspicious_words = ["login", "verify", "update", "bank", "secure", "account"]
    for word in suspicious_words:
        if word in url.lower():
            return True
    return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    img = Image.open(file)

    # تحويل الصورة إلى numpy
    img_np = np.array(img)

    # قراءة QR باستخدام OpenCV
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img_np)

    if not data:
        return "<h2>❌ No QR Code found!</h2>"

    content = data

    if re.match(r'https?://', content):
        if is_suspicious(content):
            return f"<h2>⚠️ Suspicious Link:</h2><p>{content}</p>"
        else:
            return f"<h2>✅ Safe Link:</h2><p>{content}</p>"
    else:
        return f"<h2>ℹ️ Text inside QR:</h2><p>{content}</p>"

if __name__ == '__main__':
    app.run()
