import os
import re
from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
# Ensure you have set your MONGO_URI in your environment variables
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/") 
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client.ids_database
logs_collection = db.attack_logs

def detect_intrusion(user_input):
    # 1. Signature Matching
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'"
    ]
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match (XSS/SQLi)"
    
    # 2. Anomaly: High special character density
    special_chars = re.findall(r'[<>{}[\ transfer\]\(\)\"\'/\\&%]', user_input)
    if len(user_input) > 10:
        density = len(special_chars) / len(user_input)
        if density > 0.35:
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
            logs_collection.insert_one({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": request.remote_addr,
                "payload": user_input,
                "type": reason
            })
            message = f"🚨 SECURITY ALERT: {reason} Detected!"
            status_class = "alert-danger"
        else:
            message = "✅ Input Clean: No threats detected."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    # Fetch latest 100 logs
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1).limit(100))
    
    # Process data for Chart.js
    type_counts = Counter(log.get('type', 'Unknown') for log in all_logs)
    ip_counts = Counter(log.get('ip', 'Unknown') for log in all_logs).most_common(5)
    
    chart_data = {
        "type_labels": list(type_counts.keys()),
        "type_values": list(type_counts.values()),
        "ip_labels": [item[0] for item in ip_counts],
        "ip_values": [item[1] for item in ip_counts],
        "total_count": logs_collection.count_documents({})
    }
    
    return render_template('dashboard.html', all_logs=all_logs, chart_data=chart_data)

if __name__ == '__main__':
    app.run(debug=True)
