from flask import Flask, jsonify

from core.supabase_db import get_supabase_client

app = Flask(__name__)


@app.get("/")
def health_check():
    return jsonify({"status": "ok", "service": "swiftprobe-backend"})


@app.get("/supabase")
def supabase_status():
    client = get_supabase_client()
    return jsonify({"supabase_configured": client is not None})


if __name__ == "__main__":
    app.run(debug=True)
