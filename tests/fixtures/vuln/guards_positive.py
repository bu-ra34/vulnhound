import os

from flask import Flask, redirect, request, send_file

app = Flask(__name__)


def is_safe_url(url):
    return url.startswith("/")


def validate_path_is_safe(path):
    if ".." in path:
        raise ValueError("bad")
    return path


@app.route("/a")
def guard_negative_branch():
    nxt = request.args.get("next")
    if is_safe_url(nxt):
        return redirect("/")
    return redirect(nxt)  # VH-EXPECT: open-redirect


@app.route("/b")
def conditional_expression_wrong_arm():
    nxt = request.args.get("next")
    return redirect("/" if is_safe_url(nxt) else nxt)  # VH-EXPECT: open-redirect


@app.route("/c")
def unvalidated_second_value():
    path = validate_path_is_safe(request.args["a"])
    other = request.args["b"]
    return send_file(os.path.join("/srv", path, other))  # VH-EXPECT: path-traversal


@app.route("/d")
def truthiness_is_not_validation():
    path = request.args.get("path")
    if path:
        return send_file(path)  # VH-EXPECT: path-traversal
    return send_file("/srv/index.html")


@app.route("/e")
def validated_other_branch_only():
    path = request.args.get("path")
    if request.args.get("strict"):
        path = validate_path_is_safe(path)
    return send_file(path)  # VH-EXPECT: path-traversal
