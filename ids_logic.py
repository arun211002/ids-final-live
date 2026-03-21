import re
import os
from datetime import datetime
from pymongo import MongoClient

# 1. Setup MongoDB Connection
# Replace with your actual URI or use an environment variable
MONGO_URI = "mongodb+srv://<username>:<password>@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI)
db = client['ids_database']
logs_collection = db['attack_logs']

def detect_signature_xss(payload: str):
    patterns = [
        r"<script[\s/>]", r"</script>", r"<img[\s/>]", 
        r"onerror", r"onload", r"javascript:", r"eval\s*\("
    ]
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

def score_anomaly(payload: str):
    score = 0
    if not payload: return 0
    
    # Anomaly 1: High length
    if len(payload) > 50: score += 2
    
    # Anomaly 2: Special character density
    special_chars = re.findall(r'[<>{}\[\]\(\)\"\'/\\&%]', payload)
    if len(payload) > 0:
        density = len(special_chars) / len(payload)
        if density > 0.25: score += 3

    # Anomaly 3: Encoding patterns
    if "%" in payload or "&#" in payload: score += 2

    return score

def hybrid_detect(payload: str):
    # Method 1: Signature
    if detect_signature_xss(payload):
        return True, "Signature Match"
    
    # Method 2: Anomaly
    if score_anomaly(payload) >= 2:
        return True, "Anomaly Detected"
    
    return False, "Safe"

def log_attack(src_ip, dest_ip, payload, method):
    """Log the attack details to MongoDB Atlas"""
    log_entry = {
        "time": datetime.now(), # MongoDB stores native datetime objects well
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "payload": payload,
        "method": method,
        "status": "Blocked"
    }
    # Insert into MongoDB
    logs_collection.insert_one(log_entry)
    print(f"[!] Alert: {method} logged to MongoDB.")
