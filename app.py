from flask import Flask, render_template, request
from pyzbar.pyzbar import decode
from PIL import Image
import re

app = Flask(__name__)


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
    results = decode(img)

    if not results:
        return "<h2>❌ No QR Code found or image is broken!</h2>"

    content = results[0].data.decode('utf-8')

    # إذا كان رابط
    if re.match(r'https?://', content):
        if is_suspicious(content):
            return f"<h2>⚠️ Suspicious QR Link Detected:</h2><p>{content}</p>"
        else:
            return f"<h2>✅ Safe QR Link:</h2><p>{content}</p>"
    else:
        return f"<h2>ℹ️ QR contains text:</h2><p>{content}</p>"

if __name__ == '__main__':
    app.run()