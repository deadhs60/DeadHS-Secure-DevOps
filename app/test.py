from flask import Flask, request, jsonify, render_template_string
import sqlite3
import os
import json

app = Flask(__name__)

# # SECRET KEY (secure)
# secret = os.getenv("SECRET_KEY")
# if not secret:
#     raise RuntimeError("SECRET_KEY environment variable not set")

# app.config['SECRET_KEY'] = secret

# DB connection
def get_db():
    return sqlite3.connect("users.db")

# Load reports
def load_report(filename):
    path = os.path.join("../reports", filename)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"error": "Report not found"}

# ---------------- ROUTES ---------------- #

@app.route("/")
def home():
    return "Secure App Running"

# 🔥 DASHBOARD
@app.route("/dashboard")
def dashboard():
    return render_template_string("""
    <h1>🔐 Secure DevOps Dashboard</h1>
    <button onclick="loadData()">Load Reports</button>

    <h2>SAST (Semgrep)</h2>
    <pre id="sast"></pre>

    <h2>Dependency Scan</h2>
    <pre id="dep"></pre>

    <h2>Secrets</h2>
    <pre id="sec"></pre>

    <script>
    async function loadData() {
        const sast = await fetch('/api/sast').then(r => r.json());
        document.getElementById('sast').innerText = JSON.stringify(sast, null, 2);

        const dep = await fetch('/api/dependency').then(r => r.json());
        document.getElementById('dep').innerText = JSON.stringify(dep, null, 2);

        const sec = await fetch('/api/secrets').then(r => r.json());
        document.getElementById('sec').innerText = JSON.stringify(sec, null, 2);
    }
    </script>
    """)

# API endpoints
@app.route("/api/sast")
def sast():
    return jsonify(load_report("semgrep.json"))

@app.route("/api/dependency")
def dependency():
    return jsonify(load_report("dependency.json"))

@app.route("/api/secrets")
def secrets():
    return jsonify(load_report("secrets.json"))

# LOGIN (secure)
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username.isalnum() or not password.isalnum():
        return "Invalid input"

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()
    conn.close()

    return "Login successful" if user else "Invalid credentials"

if __name__ == "__main__":
    app.run(debug=False)