import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
# IMPORTANT: For global access, replace the localhost URI with your MongoDB Atlas Connection String
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/") 

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000
)
db = client.ids_database
logs_collection = db.attack_logs

# --- HYBRID DETECTION SYSTEM ---
def detect_intrusion(user_input):
    # 1. Signature-Based
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE",
        r"window\.location", r"eval\(", r"<iframe>"
    ]
    
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match"
    
    # 2. Anomaly-Based (Character Density)
    if user_input:
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
            # Captures the REAL Public IP of the attacker from anywhere in the world
            user_ip = request.remote_addr
            
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

if __name__ == '__main__':
    # '0.0.0.0' allows the entire world (via Render/Cloud) to access your app
    # PORT is assigned dynamically by the hosting provider
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
