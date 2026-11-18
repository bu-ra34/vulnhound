import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/l")
def loop():
    prev = ""
    cur = ""
    for _ in range(3):
        os.system("echo " + cur)  # VH-EXPECT: cmdi
        cur = prev
        prev = request.args["x"]
    return "ok"


@app.route("/w")
def wloop():
    acc = ""
    parts = request.args.getlist("p")
    while parts:
        acc = acc + parts.pop()
    os.system(acc)  # VH-EXPECT: cmdi
    return "ok"
