import os
import urllib.parse
import urllib.request

from flask import Flask, abort, redirect, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = os.path.abspath("/srv/files")
ALLOWED_HOSTS = ("example.com", "static.example.com")


def validate_name(name):
    if ".." in name or name.startswith("/"):
        raise ValueError("bad name")


def ensure_inside(path, base):
    if not os.path.abspath(path).startswith(base + os.sep):
        abort(400)


def is_safe_url(url):
    return urllib.parse.urlparse(url).netloc in ALLOWED_HOSTS


@app.route("/a")
def prefix_check_then_exit():
    name = request.args["name"]
    full = os.path.abspath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):
        abort(400)
    return open(full).read()


@app.route("/b")
def validator_statement():
    name = request.args["name"]
    validate_name(name)
    return open(os.path.join(BASE, name)).read()


@app.route("/c")
def helper_guard():
    name = request.args["name"]
    path = os.path.join(BASE, name)
    ensure_inside(path, BASE)
    return open(path).read()


@app.route("/d")
def returning_validators():
    f = request.files["f"]
    return open(os.path.join(BASE, secure_filename(f.filename))).read()


@app.route("/e")
def predicate_guard_ssrf():
    url = request.args["u"]
    if not is_safe_url(url):
        abort(400)
    return urllib.request.urlopen(url).read()


@app.route("/f")
def netloc_compare_redirect():
    nxt = request.args["next"]
    if urllib.parse.urlparse(nxt).netloc != request.host:
        return redirect("/")
    return redirect(nxt)


@app.route("/g")
def positive_branch():
    nxt = request.args["next"]
    if nxt in ALLOWED_HOSTS:
        return redirect(nxt)
    return "no"


@app.route("/h")
def dotdot_check():
    name = request.args["name"]
    if ".." in name:
        abort(400)
    return open(os.path.join(BASE, name)).read()


@app.route("/i")
def assert_guard():
    name = request.args["name"]
    assert name.startswith("pub_")
    return open(os.path.join(BASE, name)).read()


@app.route("/j")
def commonpath():
    name = request.args["name"]
    p = os.path.realpath(os.path.join(BASE, name))
    if os.path.commonpath([BASE, p]) != BASE:
        abort(403)
    return open(p).read()
