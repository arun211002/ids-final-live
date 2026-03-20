import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)

# --- MONGODB CONNECTION ---
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client.ids_database
logs_collection = db.attack_logs

# --- HYBRID DETECTION SYSTEM ---
def detect_intrusion(user_input):
    # 1. SIGNATURE-BASED (Patterns)
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'" # Added SQLi signatures
    ]
    
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Detected"

    # 2. ANOMALY-BASED (Behavioral)
    # Attackers often use very long payloads or excessive special characters
    special_char_count = len(re.findall(r"[<>{}\[\]()=;']", user_input))
    
    if len(user_input) > 100:
        return True, "Anomaly: Input Too Long"
    
    if special_char_count > 5:
        return True, "Anomaly: High Special Character Density"

    return False, None

# --- ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    status_class = "alert-info"
    
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_attack, reason = detect_intrusion(user_input)
        
        if is_attack:
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "payload": user_input,
                "ip": request.remote_addr,
                "type": reason,
                "status": "Blocked"
            }
            logs_collection.insert_one(log_entry)
            message = f"🚨 Security Alert: {reason}!"
            status_class = "alert-danger"
        else:
            message = "✅ Input processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))
    return render_template('dashboard.html', logs=all_logs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
