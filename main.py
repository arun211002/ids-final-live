import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
# Replace the string below with your MongoDB Atlas URI for global access
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/") 

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000
)
db = client.ids_database
logs_collection = db.attack_logs

# --- IDS DETECTION LOGIC ---
def detect_intrusion(user_input):
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE",
        r"window\.location", r"eval\(", r"<iframe>"
    ]
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match"
    
    if user_input:
        special_chars = re.findall(r'[<>{}[\ transfer\]\(\)\"\'/\\&%]', user_input)
        if (len(special_chars) / len(user_input)) > 0.35:
            return True, "High Character Density Anomaly"
            
    return False, None

@app.route('/', methods=['GET', 'POST'])
def home():
    message = None
    status_class = None
    
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_threat, reason = detect_intrusion(user_input)
        
        if is_threat:
            # --- GLOBAL IP DETECTION FIX ---
            # If the app is behind a proxy (like Render), get the real visitor IP
            if request.headers.getlist("X-Forwarded-For"):
                user_ip = request.headers.getlist("X-Forwarded-For")[0]
            else:
                user_ip = request.remote_addr
            # -------------------------------

            logs_collection.insert_one({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": user_ip,
                "payload": user_input,
                "type": reason
            })
            message = f"🚨 SECURITY ALERT: {reason} Detected!"
            status_class = "alert-danger"
        else:
            message = "✅ Input Clean: Processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    try:
        # Fetch all logs for the global dashboard
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
    except Exception as e:
        return f"Dashboard Error: {e}", 500

if __name__ == '__main__':
    # Listen on 0.0.0.0 for global access
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
