import re
import os
from datetime import datetime

# --- ENHANCED ATTACK VECTORS ---
# These catch the malicious scripts that were previously marked as "Safe"
SIGNATURES = {
    "Signature Match": r"<script.*?>|javascript:|alert\(|confirm\(|prompt\(|document\.cookie",
    "Malicious HTML Pattern": r"<(svg|details|iframe|audio|video|img|body|style).*?(on\w+\s*=)",
    "SQL/NoSQL Injection": r"(' OR '1'='1'|UNION SELECT|DROP TABLE|\$gt|\$ne|\$where|\$regex)",
    "Path Traversal": r"(\.\./|\.\.\\|/etc/passwd|boot\.ini)",
    "Command Injection": r"(;|&&|\|\||`|\$\(|python\s+-c|bash\s+-i)"
}

def detect_intrusion(user_input):
    """
    Main detection engine.
    Returns: (is_threat, reason)
    """
    if not user_input:
        return False, None

    # 1. Broadened Signature Check (Instant Block)
    for reason, pattern in SIGNATURES.items():
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, reason
    
    # 2. Advanced Anomaly Scoring
    # Matches your dashboard legend: "High Symbol Density" & "Input Too Long"
    score = 0
    
    # Check Special Character Density
    special_chars = re.findall(r'[<>{}\[\]\(\)\"\'/\\&%#;=|]', user_input)
    if len(user_input) > 0:
        density = len(special_chars) / len(user_input)
        if density > 0.35:
            return True, "High Character Density Anomaly"
        elif density > 0.20:
            return True, "High Symbol Density"

    # Check for Input Length
    if len(user_input) > 150:
        return True, "Anomaly: Input Too Long"
            
    return False, None
