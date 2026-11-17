import os
import posixpath
from urllib.parse import urlparse

from flask import Flask, abort, redirect, request, send_file

app = Flask(__name__)
ALLOWED_HOSTS = ("example.com",)


def is_safe_url(url):
    return urlparse(url).netloc in ALLOWED_HOSTS


def validate_path_is_safe(path):
    if ".." in path.split("/") or path.startswith("/"):
        raise ValueError("bad path")
    return path


def get_redirect_target(param="next"):
    target = request.values.get(param)
    if target and is_safe_url(target):
        return target
    return None


@app.route("/a")
def helper_with_positive_guard():
    return redirect(get_redirect_target() or "/")


@app.route("/b")
def guard_in_branch():
    nxt = request.args.get("next")
    if nxt and is_safe_url(nxt):
        return redirect(nxt)
    return redirect("/")


@app.route("/c")
def conditional_expression():
    nxt = request.args.get("next")
    return redirect(nxt if is_safe_url(nxt) else "/")


@app.route("/d")
def and_chain():
    nxt = request.args.get("next")
    return redirect(is_safe_url(nxt) and nxt or "/")


@app.route("/e")
def predicate_then_use():
    p = request.args.get("p")
    if validate_path_is_safe(p):
        return send_file(os.path.join("/srv", p))
    abort(404)


@app.route("/f")
def reassigned_validator_in_branch():
    path = request.args.get("path")
    if path:
        path = validate_path_is_safe(path)
        full = posixpath.join("/srv/attachments", path)
        return send_file(full)
    return send_file("/srv/index.html")


@app.route("/g")
def reassigned_validator_reread():
    path = request.args["path"]
    path = validate_path_is_safe(path)
    base = posixpath.join("/srv", path)
    return send_file(os.path.abspath(base))


@app.route("/h")
def empty_is_harmless():
    path = request.args.get("path")
    if not path:
        return send_file(path)
    abort(400)
