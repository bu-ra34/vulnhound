import os
import shlex

from flask import Flask, request

app = Flask(__name__)


@app.route("/l")
def loop():
    prev = ""
    cur = ""
    for _ in range(3):
        os.system("echo " + cur)
        cur = prev
        prev = shlex.quote(request.args["x"])
    return "ok"


@app.route("/w")
def wloop():
    acc = ""
    parts = ["a", "b"]
    while parts:
        acc = acc + parts.pop()
    os.system(acc)
    return "ok"
