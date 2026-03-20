import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
# Use Environment Variable for Render, or fallback to local for testing
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/") 

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client.ids_database
    logs_collection = db.attack_logs
    client.admin.command('ping') # Test connection
except Exception as e:
    print(f"DB Connection Error: {e}")

# --- HYBRID DETECTION LOGIC ---
def detect_intrusion(user_input):
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE"
    ]
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match"
    
    if user_input and len(user_input) > 0:
        special_chars = re.findall(r'[<>{}[\ transfer\]\(\)\"\'/\\&%]', user_input)
        if (len(special_chars) / len(user_input)) > 0.35:
            return True, "High Character Density"
            
    return False, None

@app.route('/', methods=['GET', 'POST'])
def home():
    message = None
    status_class = None
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_threat, reason = detect_intrusion(user_input)
        
        if is_threat:
            # REAL IP DETECTION (Captures Global IPs on Render)
            if request.headers.getlist("X-Forwarded-For"):
                user_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
            else:
                user_ip = request.remote_addr

            logs_collection.insert_one({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": user_ip,
                "payload": user_input,
                "type": reason
            })
            message = f"🚨 SECURITY ALERT: {reason}!"
            status_class = "alert-danger"
        else:
            message = "✅ Input Clean."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))
    type_counts = Counter(log.get('type', 'Unknown') for log in all_logs)
    ip_counts = Counter(log.get('ip', 'Unknown') for log in all_logs).most_common(10)
    
    chart_data = {
        "type_labels": list(type_counts.keys()),
        "type_values": list(type_counts.values()),
        "ip_labels": [item[0] for item in ip_counts],
        "ip_values": [item[1] for item in ip_counts],
        "total_count": len(all_logs)
    }
    return render_template('dashboard.html', all_logs=all_logs, chart_data=chart_data)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
