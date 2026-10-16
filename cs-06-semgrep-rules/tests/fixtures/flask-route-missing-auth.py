from flask import Flask, Blueprint
from flask_login import login_required
from flask_jwt_extended import jwt_required

app = Flask(__name__)
bp = Blueprint("bp", __name__)


# ruleid: flask-route-missing-auth
@app.route("/admin")
def admin():
    return "secret"


# ruleid: flask-route-missing-auth
@app.route("/users/<int:uid>", methods=["DELETE"])
def delete_user(uid):
    return "deleted"


# ruleid: flask-route-missing-auth
@bp.route("/export")
def export():
    return "data"


# ruleid: flask-route-missing-auth
@app.get("/reports")
def reports():
    return "r"


# ruleid: flask-route-missing-auth
@app.route("/cache")
@cache.cached(timeout=50)
def cached():
    return "c"


# ok: flask-route-missing-auth
@app.route("/profile")
@login_required
def profile():
    return "p"


# ok: flask-route-missing-auth
@app.route("/api/items")
@jwt_required()
def items():
    return "i"


# ok: flask-route-missing-auth
@login_required
@app.route("/settings")
def settings():
    return "s"


# ok: flask-route-missing-auth
@bp.route("/billing")
@require_auth
def billing():
    return "b"


# ok: flask-route-missing-auth
@app.route("/health")
@public
def health():
    return "ok"


# ok: flask-route-missing-auth
def helper():
    return "not a route"
