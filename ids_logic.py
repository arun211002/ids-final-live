from tinydb import TinyDB
from datetime import datetime
import re

db = TinyDB("db.json")

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
    
    # Anomaly 2: Special character density (XSS specific)
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
    """Fixed: Now accepts 4 arguments to prevent TypeError"""
    db.insert({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "payload": payload,
        "method": method,
        "status": "Blocked"
    })