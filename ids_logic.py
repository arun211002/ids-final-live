import re

# Ordered rules: first match wins so labels stay deterministic in dashboard charts.
SIGNATURE_RULES = [
    (
        "Signature: Malicious Pattern Detected",
        r"<\s*script\b|javascript\s*:|document\.cookie|on\w+\s*=|eval\s*\(|"
        r"<\s*(iframe|object|embed|meta|svg)\b"
    ),
    (
        "Signature: Malicious Pattern",
        r"%3c\s*script|&lt;\s*script|data\s*:\s*text\/html|window\.location|settimeout\s*\(|setinterval\s*\("
    ),
    (
        "Signature Match",
        r"\b(select\s+.+\s+from|union\s+select|drop\s+table|insert\s+into|delete\s+from)\b|"
        r"['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1|\$where|\$regex|\$gt|\$ne"
    ),
    (
        "Signature Detected",
        r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|cmd\.exe|/bin/sh|\bcat\s+/etc/passwd\b|"
        r"(?:\|\||&&|;)\s*(?:cat|ls|whoami|id|bash|sh|cmd|powershell|curl|wget|python|perl|nc|netstat)\b|"
        r"`[^`]+`|\$\()"
    ),
]

SPECIAL_CHAR_PATTERN = re.compile(r"[^a-zA-Z0-9\s]")
REPEATED_SYMBOL_PATTERN = re.compile(r"([^a-zA-Z0-9\s])\1{5,}")

def detect_intrusion(user_input):
    """
    Main detection engine.
    Returns: (is_threat, reason)
    """
    if not user_input:
        return False, None

    if not isinstance(user_input, str):
        user_input = str(user_input)

    user_input = user_input.strip()
    if not user_input:
        return False, None

    # 1. Signature detection
    for reason, pattern in SIGNATURE_RULES:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True, reason

    # 2. Length anomalies
    payload_len = len(user_input)
    if payload_len > 500:
        return True, "Anomaly: Payload Length Too High"
    if payload_len > 250:
        return True, "Anomaly: Input Length Exceeded"
    if payload_len > 150:
        return True, "Anomaly: Input Too Long"

    # 3. Density anomalies
    special_chars = SPECIAL_CHAR_PATTERN.findall(user_input)
    density = len(special_chars) / payload_len

    if density > 0.40:
        return True, "High Character Density Anomaly"
    if density > 0.30:
        return True, "Anomaly: High Special Character Density"
    if density > 0.22:
        return True, "Anomaly: High Symbol Density"
    if density > 0.18:
        return True, "High Character Density"

    # 4. Generic anomaly fallback for noisy payloads.
    if REPEATED_SYMBOL_PATTERN.search(user_input):
        return True, "Anomaly Detected"

    # 5. Mark suspicious control bytes that do not match known signatures.
    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in user_input):
        return True, "Unknown"

    return False, None
