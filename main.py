import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)

# --- MONGODB CONNECTION (Atlas Ready) ---
# If you are on Render, it uses the Environment Variable.
# If you are local, it falls back to localhost.
MONGO_URI = os.getenv("MONGO_URI") 

try:
    # 2-second timeout prevents the "infinite circling" if DB is unreachable
    client = MongoClient(
        MONGO_URI, 
        serverSelectionTimeoutMS=2000,
        connectTimeoutMS=2000
    )
    db = client.ids_database
    logs_collection = db.attack_logs
    # Ping the database to ensure it's actually awake
    client.admin.command('ping')
    print("DATABASE CONNECTED SUCCESSFULLY")
except Exception as e:
    print(f"DATABASE CONNECTION ERROR: {e}")
    print("Ensure MongoDB Compass is CONNECTED or Atlas URI is correct.")

# --- HYBRID DETECTION ENGINE ---
def detect_intrusion(user_input):
    # 1. Signature-Based Detection
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE",
        r"window\.location", r"eval\(", r"<iframe>"
    ]
    
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match"
    
    # 2. Anomaly-Based Detection (High Character Density)
    if user_input and len(user_input) > 0:
        # Detects clusters of symbols like < > / \ % & ^
        special_chars = re.findall(r'[<>{}[\ transfer\]\(\)\"\'/\\&%]', user_input)
        density = len(special_chars) / len(user_input)
        if density > 0.35:
            return True, "High Character Density Anomaly"
            
    return False, None

# --- ROUTE: ATTACK PORTAL (HOME) ---
@app.route('/', methods=['GET', 'POST'])
def home():
    message = None
    status_class = None
    
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        is_threat, reason = detect_intrusion(user_input)
        
        if is_threat:
            # --- THE GLOBAL IP PROXY FIX ---
            # Priority 1: X-Forwarded-For (From Render/Cloud)
            # Priority 2: remote_addr (From Localhost)
            if request.headers.getlist("X-Forwarded-For"):
                user_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
            else:
                user_ip = request.remote_addr
            
            # Log the attack to MongoDB
            try:
                logs_collection.insert_one({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": user_ip,
                    "payload": user_input,
                    "type": reason
                })
            except Exception as e:
                print(f"Logging failed: {e}")
            
            message = f"🚨 SECURITY ALERT: {reason} Detected!"
            status_class = "alert-danger"
        else:
            message = "✅ Input Clean: Processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

# --- ROUTE: COMMAND DASHBOARD ---
@app.route('/dashboard')
def dashboard():
    try:
        # Fetch logs and sort by newest first
        all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))
    except:
        all_logs = []

    # Prepare data for Chart.js
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
    # PORT is dynamic for Render; 0.0.0.0 listens to the entire world
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
