import os
import subprocess
import urllib.request

from flask import Flask, redirect, request

app = Flask(__name__)
BASE = "/srv/files"


def log(msg):
    print(msg)


@app.route("/a")
def check_without_exit():
    name = request.args["name"]
    if not name.startswith("ok_"):
        log("suspicious")  # no exit: still tainted below
    return open(os.path.join(BASE, name)).read()  # VH-EXPECT: path-traversal


@app.route("/b")
def guard_on_one_branch_only():
    url = request.args["u"]
    if request.args.get("strict"):
        if not url.startswith("https://example.com/"):
            raise ValueError("bad")
    return urllib.request.urlopen(url).read()  # VH-EXPECT: ssrf


@app.route("/c")
def guard_on_wrong_variable():
    nxt = request.args["next"]
    other = request.args["other"]
    if not nxt.startswith("/"):
        return "bad", 400
    return redirect(other)  # VH-EXPECT: open-redirect


@app.route("/d")
def blacklist_does_not_clear_cmdi():
    host = request.args["host"]
    if not host.startswith("10."):
        return "bad", 400
    subprocess.run("ping " + host, shell=True)  # VH-EXPECT: cmdi
    return "ok"
