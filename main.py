import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
# If deploying to Render, set the MONGO_URI in Environment Variables.
# If testing locally, ensure MongoDB Compass is running.
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/") 

try:
    # Added timeouts so the site doesn't "spin" forever if DB is down
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client.ids_database
    logs_collection = db.attack_logs
    # Trigger a quick command to check if connection is alive
    client.admin.command('ping')
except Exception as e:
    print(f"DATABASE CONNECTION ERROR: {e}")

# --- DETECTION LOGIC ---
def detect_intrusion(user_input):
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'"
    ]
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match"
    
    if user_input and len(user_input) > 0:
        special_chars = re.findall(r'[<>{}[\ transfer\]\(\)\"\'/\\&%]', user_input)
        if (len(special_chars) / len(user_input)) > 0.35:
            return True, "Anomaly Detected"
    return False, None

@app.route('/', methods=['GET', 'POST'])
def home():
    message = None
    status_class = None
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_threat, reason = detect_intrusion(user_input)
        if is_threat:
            # --- THE WORLD IP FIX ---
            # Priority 1: X-Forwarded-For (Render/Global)
            # Priority 2: remote_addr (Local)
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
    try:
        # Fetching all logs from the database
        all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))
        
        type_counts = Counter(log.get('type', 'Unknown') for log in all_logs)
        # Showing the top source of attacks
        ip_counts = Counter(log.get('ip', 'Unknown') for log in all_logs).most_common(10)
        
        chart_data = {
            "type_labels": list(type_counts.keys()),
            "type_values": list(type_counts.values()),
            "ip_labels": [item[0] for item in ip_counts],
            "ip_values": [item[1] for item in ip_counts],
            "total_count": len(all_logs)
        }
        return render_template('dashboard.html', all_logs=all_logs, chart_data=chart_data)
    except Exception as e:
        return f"Database error: {e}. Ensure MongoDB is running."

if __name__ == '__main__':
    # Listen on all IPs (0.0.0.0) for network/global access
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
