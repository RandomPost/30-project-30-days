from flask import Flask, request
import sqlite3

app = Flask(__name__)
conn = sqlite3.connect("app.db")
db = None


def vulnerable(name, uid):
    cur = conn.cursor()
    # ruleid: flask-sql-string-formatting
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: flask-sql-string-formatting
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    # ruleid: flask-sql-string-formatting
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: flask-sql-string-formatting
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: flask-sql-string-formatting
    db.session.execute(f"DELETE FROM users WHERE id = {uid}")
    # ruleid: flask-sql-string-formatting
    db.engine.execute("SELECT * FROM t WHERE x = %s" % uid)
    # ruleid: flask-sql-string-formatting
    conn.execute(f"UPDATE users SET name = '{name}'")


def vulnerable_query_built_first(name, uid, table):
    # Query assembled into a variable first, executed later (found in a real repo).
    q1 = "SELECT * FROM users WHERE name = '%s';" % name
    q2 = f"SELECT * FROM {table} WHERE id = {uid}"
    q3 = "SELECT * FROM users WHERE name = '{}'".format(name)
    q4 = "SELECT * FROM users WHERE name = '" + name + "'"
    cur = conn.cursor()
    # ruleid: flask-sql-string-formatting
    cur.execute(q1)
    # ruleid: flask-sql-string-formatting
    db.engine.execute(q2)
    # ruleid: flask-sql-string-formatting
    cur.execute(q3)
    # ruleid: flask-sql-string-formatting
    cur.execute(q4)


def safe_query_built_first(name):
    q = "SELECT * FROM users WHERE name = ?"
    label = "user %s" % name
    cur = conn.cursor()
    # ok: flask-sql-string-formatting
    cur.execute(q, (name,))
    # ok: flask-sql-string-formatting
    log.execute(label)


def safe(name, uid):
    cur = conn.cursor()
    # ok: flask-sql-string-formatting
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    # ok: flask-sql-string-formatting
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    # ok: flask-sql-string-formatting
    cur.execute("SELECT * FROM users")
    # ok: flask-sql-string-formatting
    db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})
    # ok: flask-sql-string-formatting
    print(f"looking up {name}")
    # ok: flask-sql-string-formatting
    log.execute("done %s" % name)
