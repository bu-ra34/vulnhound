import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # VH-EXPECT: sqli
    return str(cur.fetchall())


@app.route("/user2")
def user2():
    uid = request.form["id"]
    conn = sqlite3.connect("app.db")
    q = f"DELETE FROM users WHERE id = {uid}"
    conn.execute(q)  # VH-EXPECT: sqli
    return "ok"
