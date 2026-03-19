from flask import Flask, render_template, request, render_template_string
import ids_logic
import os

# Initialize Flask with the correct template folder
app = Flask(__name__, template_folder='templates')

@app.route('/')
def home():
    return render_template('xss_both_demo.html')

@app.route('/check')
def check_xss():
    user_input = request.args.get('input', '')
    client_ip = request.remote_addr
    dest_ip = "127.0.0.1"

    # Use the hybrid detection logic
    is_detected, reason = ids_logic.hybrid_detect(user_input)

    if is_detected:
        ids_logic.log_attack(client_ip, dest_ip, user_input, reason)
        return f"""
        <div style="font-family:sans-serif; background:#220000; color:#ff4444; padding:20px; border:2px solid red;">
            <h2>🚨 XSS Attack Blocked by IDS!</h2>
            <p><strong>Detection Method:</strong> {reason}</p>
            <p><strong>Malicious Payload:</strong> <code>{user_input}</code></p>
            <a href="/" style="color:white;">Try another test</a>
        </div>
        """
    
    return f"""
    <div style="font-family:sans-serif; color:green; padding:20px;">
        <h3>✅ Input processed safely</h3>
        <p>Your input: {user_input}</p>
        <a href="/">Back to home</a>
    </div>
    """

@app.route('/dashboard')
def dashboard():
    logs = ids_logic.db.all()
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True, port=8000)