from urllib.parse import urlparse, urlsplit

import requests
from django.shortcuts import redirect as dj_redirect
from django.urls import reverse
from flask import Flask, redirect, request, url_for

app = Flask(__name__)
BASE = "https://api.example.com/"
TARGET_URI = app.config.get("TARGET_URI", "http://backend.internal")


@app.route("/a")
def path_prefix():
    return redirect("/items/" + request.args["name"])


@app.route("/b")
def path_prefix_fstring():
    return redirect(f"/items/{request.args['name']}?x=1")


@app.route("/c")
def path_prefix_percent():
    return redirect("/items/%s" % request.args["name"])


@app.route("/d")
def path_prefix_format():
    return redirect("/items/{}".format(request.args["name"]))


@app.route("/e")
def absolute_fixed_host():
    return requests.get("https://api.example.com/v1/" + request.args["name"]).text


@app.route("/f")
def config_base_url():
    return requests.get(f"{TARGET_URI}/{request.args['path']}").text


@app.route("/g")
def base_constant_variable():
    return requests.get(BASE + request.args["name"]).text


@app.route("/h")
def same_page():
    return redirect(request.path)


@app.route("/i")
def same_page_query():
    return redirect(request.script_root + request.full_path.rstrip("?"))


@app.route("/j")
def path_and_query():
    return redirect(request.path + "?" + request.query_string.decode())


@app.route("/k")
def url_for_with_query():
    return redirect(url_for("index") + "?next=" + request.args["next"])


@app.route("/l")
def reverse_with_query():
    return dj_redirect(reverse("home") + "?" + request.args["q"])


@app.route("/m")
def recombined_path():
    parts = urlparse(request.args["next"])
    return redirect(parts.path + "?" + parts.query)


@app.route("/n")
def recombined_path_split():
    u = urlsplit(request.args["next"])
    return redirect(f"{u.path}?{u.query}")


def merged_with_param_default(nxt=None):
    target = nxt
    if not target:
        target = request.script_root + request.path
    return redirect(target)
