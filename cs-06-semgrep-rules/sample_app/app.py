"""DELIBERATELY VULNERABLE demo app. Never deploy. It exists so the rule pack has
something real to find: one example of each issue the rules cover."""

import pickle
import sqlite3
import subprocess

import jwt
import yaml
from flask import Flask, jsonify, request
from flask_login import login_required

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "dev-secret"
db = sqlite3.connect("demo.db", check_same_thread=False)


@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    row = db.execute(f"SELECT id FROM users WHERE name = '{name}'").fetchone()
    token = jwt.encode({"sub": row[0]}, "hunter2-signing-key", algorithm="HS256")
    return jsonify(token=token)


@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host")
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return out.stdout


@app.route("/import", methods=["POST"])
@login_required
def import_config():
    cfg = yaml.load(request.data)
    blob = pickle.loads(request.files["state"].read())
    return jsonify(cfg=cfg, state=str(blob))


@app.route("/admin/users")
def admin_users():
    return jsonify(users=[r[0] for r in db.execute("SELECT name FROM users")])
