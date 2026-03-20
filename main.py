import os
import re
from flask import Flask, render_template, request
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)

# --- MONGODB CONNECTION ---
# No more db.json! We fetch the link from Render's Environment Variables
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client.ids_database
logs_collection = db.attack_logs

# --- IDS DETECTION LOGIC ---
def is_xss_attack(payload):
    """Detects XSS signatures in user input."""
    patterns = [r"<script.*?>", r"javascript:", r"onload=", r"onerror=", r"<img.*?src="]
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

# --- ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    status_class = "alert-info"
    
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        if is_xss_attack(user_input):
            # SAVE TO MONGODB instead of a file
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "payload": user_input,
                "ip": request.remote_addr,
                "status": "Blocked"
            }
            logs_collection.insert_one(log_entry)
            message = "🚨 Security Alert: XSS Attack Blocked & Logged to Cloud!"
            status_class = "alert-danger"
        else:
            message = "✅ Input processed safely."
            status_class = "alert-success"
            
    return render_template('xss_both_demo.html', message=message, status_class=status_class)

@app.route('/dashboard')
def dashboard():
    # FETCH FROM MONGODB (Newest attacks first)
    all_logs = list(logs_collection.find({}, {'_id': 0}).sort("timestamp", -1))
    return render_template('dashboard.html', logs=all_logs)

if __name__ == '__main__':
    # Render uses port 10000 by default
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
