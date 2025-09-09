import os, psycopg
from flask import Flask, request, jsonify
app = Flask(__name__)
DB = os.environ.get("DATABASE_URL")

@app.get("/")
def home():
    return "CSCI 390 Auth Demo (Docker): OK"

@app.get("/healthz")
def health():
    try:
        with psycopg.connect(DB) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

@app.post("/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    user = data.get("user","guest")
    return jsonify(message=f"login attempt for {user}")
