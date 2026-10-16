import os

import jwt
from flask import Flask

app = Flask(__name__)
SECRET = "super-secret-signing-key"

# ruleid: hardcoded-jwt-secret
app.config["JWT_SECRET_KEY"] = "change-me-please"
# ruleid: hardcoded-jwt-secret
app.config.update(JWT_SECRET_KEY="another-hardcoded-key")
# ruleid: hardcoded-jwt-secret
app.config["SECRET_KEY"] = "dev"


def vulnerable(user, token):
    # ruleid: hardcoded-jwt-secret
    jwt.encode({"sub": user}, "hardcoded-secret", algorithm="HS256")
    # ruleid: hardcoded-jwt-secret
    jwt.decode(token, "hardcoded-secret", algorithms=["HS256"])
    # ruleid: hardcoded-jwt-secret
    jwt.encode({"sub": user}, key="hardcoded-secret", algorithm="HS256")
    # ruleid: hardcoded-jwt-secret
    jwt.encode({"sub": user}, SECRET, algorithm="HS256")


def safe(user, token):
    # ok: hardcoded-jwt-secret
    jwt.encode({"sub": user}, os.environ["JWT_SECRET"], algorithm="HS256")
    # ok: hardcoded-jwt-secret
    jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    # ok: hardcoded-jwt-secret
    jwt.decode(token, load_key(), algorithms=["HS256"])
    # ok: hardcoded-jwt-secret
    jwt.decode(token, options={"verify_signature": False})


# ok: hardcoded-jwt-secret
app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
# ok: hardcoded-jwt-secret
app.config["JSON_SORT_KEYS"] = False
