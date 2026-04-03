from flask import Flask, request, render_template
import subprocess
import sqlite3
import os

app = Flask(__name__)

# ✅ Secure: No hardcoded fallback
secret = os.getenv("SECRET_KEY")
if not secret:
    raise RuntimeError("SECRET_KEY environment variable not set")

app.config['SECRET_KEY'] = secret

# Connect to DB
def get_db():
    return sqlite3.connect("users.db")

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ✅ Input validation
    if not username.isalnum() or not password.isalnum():
        return "Invalid input"

    conn = get_db()
    cursor = conn.cursor()

    # ✅ Parameterized query (prevents SQL Injection)
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    else:
        return "Invalid credentials"
    
@app.route("/scan/<scan_type>")
def run_scan(scan_type):
    try:
        if scan_type == "semgrep":
            result = subprocess.check_output(
                ["semgrep", "--config=p/owasp-top-ten", "."],
                stderr=subprocess.STDOUT
            )

        elif scan_type == "dependency":
            result = subprocess.check_output(
                ["pip-audit"],
                stderr=subprocess.STDOUT
            )

        elif scan_type == "secret":
            result = subprocess.check_output(
                ["docker", "run", "--rm",
                 "-v", f"{os.getcwd()}:/repo",
                 "ghcr.io/trufflesecurity/trufflehog:latest",
                 "filesystem", "/repo"],
                stderr=subprocess.STDOUT
            )

        elif scan_type == "zap":
            result = subprocess.check_output(
                ["docker", "run", "-t",
                 "-v", f"{os.getcwd()}/zap-output:/zap/wrk",
                 "ghcr.io/zaproxy/zaproxy:stable",
                 "zap-baseline.py",
                 "-t", "http://host.docker.internal:5000"],
                stderr=subprocess.STDOUT
            )

        else:
            return "Invalid scan type"

        return result.decode("utf-8")

    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8")    

if __name__ == '__main__':
    app.run(debug=False)