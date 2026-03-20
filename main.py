import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# --- MONGODB CONNECTION ---
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client.ids_database
logs_collection = db.attack_logs

def detect_intrusion(user_input):
    signatures = [
        r"<script.*?>", r"javascript:", r"onload=", r"onerror=", 
        r"<img.*?src=", r"alert\(", r"document\.cookie",
        r"SELECT .* FROM", r"UNION SELECT", r"OR '1'='1'", r"DROP TABLE"
    ]
    for pattern in signatures:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, "Signature Match"
    
    # Anomaly: High special character density
    special_chars = re.findall(r'[<>{}[\ transfer\]\(\)\"\'/\\&%]', user_input)
    if len(user_input) > 0 and (len(special_chars) / len(user_input)) > 0.3:
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
            message = f"🚨 Security Alert: {reason}!"
            status_class = "alert-danger"
        else:
            message = "✅ Input verified and processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    # Fetch logs and prepare data for the new dashboard
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1).limit(100))
    
    type_counts = Counter(log.get('type', 'Unknown') for log in all_logs)
    ip_counts = Counter(log.get('ip', 'Unknown') for log in all_logs).most_common(5)
    
    chart_data = {
        "type_labels": list(type_counts.keys()),
        "type_values": list(type_counts.values()),
        "ip_labels": [item[0] for item in ip_counts],
        "ip_values": [item[1] for item in ip_counts],
        "total_count": len(all_logs)
    }
    
    return render_template('dashboard.html', all_logs=all_logs, chart_data=chart_data)

if __name__ == '__main__':
    app.run(debug=True)
