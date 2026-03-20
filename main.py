import os
import re
from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client.ids_database
logs_collection = db.attack_logs

# --- HYBRID DETECTION SYSTEM ---
def detect_intrusion(user_input):
    # 1. SIGNATURE-BASED DETECTION (Known Bad Patterns)
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE",
        r"window\.location", r"eval\(", r"<iframe>"
    ]
    
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature: Malicious Pattern"

    # 2. ANOMALY-BASED DETECTION (Suspicious Behavior)
    special_chars = re.findall(r"[<>{}\[\]()=;']", user_input)
    
    # Rule: Input is suspiciously long
    if len(user_input) > 120:
        return True, "Anomaly: Input Length Exceeded"
    
    # Rule: Too many symbols (often used in obfuscation)
    if len(special_chars) > 8:
        return True, "Anomaly: High Symbol Density"

    return False, None

# --- ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    status_class = "alert-info"
    
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_attack, reason = detect_intrusion(user_input)
        
        # Get REAL User IP (Bypassing Render Proxy)
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]

        if is_attack:
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "payload": user_input,
                "ip": user_ip,
                "type": reason,
                "status": "Blocked"
            }
            logs_collection.insert_one(log_entry)
            message = f"🚨 Security Alert: {reason}!"
            status_class = "alert-danger"
        else:
            message = "✅ Input verified and processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    # 1. Fetch all logs from MongoDB
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))

    # 2. Prepare Data for Charts in dashboard.html
    type_counts = Counter(log.get('type', 'Unknown') for log in all_logs)
    ip_counts = Counter(log.get('ip', 'Unknown') for log in all_logs).most_common(5)
    
    chart_data = {
        "type_labels": list(type_counts.keys()),
        "type_values": list(type_counts.values()),
        "ip_labels": [item[0] for item in ip_counts],
        "ip_values": [item[1] for item in ip_counts],
        "total_count": len(all_logs)
    }

    # IMPORTANT: Ensure your file is named dashboard.html in the templates folder
    return render_template('dashboard.html', logs=all_logs, chart_data=chart_data)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
