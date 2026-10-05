from flask import Flask, request, jsonify
from pathlib import Path
import json, secrets, hmac, hashlib, os
from datetime import datetime, timezone

app = Flask(__name__)
DB = Path("licenses.json")
SECRET = os.environ.get("LICENSE_SECRET")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

if not SECRET or not ADMIN_TOKEN:
    raise RuntimeError("LICENSE_SECRET and ADMIN_TOKEN must be configured")

def load_db():
    if not DB.exists():
        return {}
    return json.loads(DB.read_text())

def save_db(db):
    DB.write_text(json.dumps(db, indent=2))

def admin_ok():
    supplied = request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(supplied, ADMIN_TOKEN)

def make_signature(key, device):
    msg = f"{key}|{device}".encode()
    return hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()

def make_key():
    raw = secrets.token_hex(8).upper()
    return f"DM-{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:]}"

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/admin/create")
def create():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    try:
        days = max(1, int(body.get("days", 30)))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_days"}), 400

    key = make_key()
    db = load_db()
    db[key] = {
        "expires": datetime.now(timezone.utc).timestamp() + days * 86400,
        "device": None,
        "revoked": False
    }
    save_db(db)
    return jsonify({"key": key, "days": days})

@app.post("/admin/revoke")
def revoke():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    key = body.get("key", "")
    db = load_db()
    if key not in db:
        return jsonify({"error": "unknown_key"}), 404
    db[key]["revoked"] = True
    save_db(db)
    return jsonify({"revoked": True})

@app.post("/activate")
def activate():
    body = request.get_json(silent=True) or {}
    key, device = body.get("key", ""), body.get("device", "")
    db = load_db()
    lic = db.get(key)

    if not lic or lic["revoked"]:
        return jsonify({"valid": False, "error": "invalid_key"}), 403
    if lic["expires"] < datetime.now(timezone.utc).timestamp():
        return jsonify({"valid": False, "error": "expired"}), 403

    if lic["device"] is None:
        lic["device"] = device
        save_db(db)
    elif lic["device"] != device:
        return jsonify({"valid": False, "error": "already_bound"}), 403

    return jsonify({
        "valid": True,
        "expires": lic["expires"],
        "signature": make_signature(key, device)
    })

@app.post("/verify")
def verify():
    body = request.get_json(silent=True) or {}
    key, device, sig = body.get("key", ""), body.get("device", ""), body.get("signature", "")
    db = load_db()
    lic = db.get(key)

    valid = bool(
        lic and not lic["revoked"]
        and lic["device"] == device
        and lic["expires"] >= datetime.now(timezone.utc).timestamp()
        and hmac.compare_digest(sig, make_signature(key, device))
    )
    return jsonify({"valid": valid, "expires": lic["expires"] if lic else None})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
