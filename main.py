import os
import re
from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION WITH ANTI-HANG TIMEOUTS ---
MONGO_URI = os.getenv("MONGO_URI")

# We add specific timeouts to prevent the "rotating cursor" issue
client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000, # 5s to find the server
    connectTimeoutMS=10000,        # 10s to establish connection
    socketTimeoutMS=15000,         # 15s for data transfer
    retryWrites=True
)
db = client.ids_database
logs_collection = db.attack_logs

# --- HYBRID DETECTION SYSTEM (Signatures + Anomalies) ---
def detect_intrusion(user_input):
    # 1. SIGNATURE-BASED: Matching known 120+ attack patterns
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE",
        r"window\.location", r"eval\(", r"<iframe>", r"document\.write"
    ]
    
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature: Malicious Pattern"

    # 2. ANOMALY-BASED: Behavioral detection
    special_chars = re.findall(r"[<>{}\[\]()=;']", user_input)
    
    if len(user_input) > 120:
        return True, "Anomaly: Input Length Exceeded"
    
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
        
        # CAPTURE REAL IP: Bypassing Render's proxy to see the actual attacker
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]

        if is_attack:
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "payload": user_input,
                "ip": user_ip,
                "type": reason,
                "status": "Blocked"
            }
            # Try/Except prevents the site from freezing if MongoDB is slow
            try:
                logs_collection.insert_one(log_entry)
            except Exception as e:
                print(f"Database Log Error: {e}")
            
            message = f"🚨 Security Alert: {reason}!"
            status_class = "alert-danger"
        else:
            message = "✅ Input verified and processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    try:
        # Limit to 200 logs to prevent memory crashes on Free Tier
        all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1).limit(200))

        # Data processing for your Chart.js graphs
        type_counts = Counter(log.get('type', 'Unknown') for log in all_logs)
        ip_counts = Counter(log.get('ip', 'Unknown') for log in all_logs).most_common(5)
        
        chart_data = {
            "type_labels": list(type_counts.keys()),
            "type_values": list(type_counts.values()),
            "ip_labels": [item[0] for item in ip_counts],
            "ip_values": [item[1] for item in ip_counts],
            "total_count": len(all_logs)
        }
    except Exception as e:
        print(f"Dashboard Load Error: {e}")
        chart_data = {"type_labels":[], "type_values":[], "ip_labels":[], "ip_values":[], "total_count":0}
        all_logs = []

    return render_template('dashboard.html', logs=all_logs, chart_data=chart_data)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
