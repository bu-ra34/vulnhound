from urllib.parse import urljoin

import requests
from flask import Flask, redirect, request

app = Flask(__name__)
BASE = "https://api.example.com/"


@app.route("/a")
def whole_value():
    return redirect(request.args["next"])  # VH-EXPECT: open-redirect


@app.route("/b")
def tainted_prefix():
    return redirect(request.args["next"] + "/done")  # VH-EXPECT: open-redirect


@app.route("/c")
def bare_slash_prefix():
    return redirect("/" + request.args["next"])  # VH-EXPECT: open-redirect


@app.route("/d")
def scheme_only_prefix():
    return redirect(f"https://{request.args['host']}/x")  # VH-EXPECT: open-redirect


@app.route("/e")
def fetch_url():
    return requests.get(request.args["url"]).text  # VH-EXPECT: ssrf


@app.route("/f")
def fetch_join():
    return requests.get(urljoin(BASE, request.args["u"])).text  # VH-EXPECT: ssrf


@app.route("/g")
def fetch_host_in_prefix():
    return requests.get("http://" + request.args["h"] + "/status").text  # VH-EXPECT: ssrf


@app.route("/h")
def percent_prefix():
    return redirect("%s/home" % request.args["next"])  # VH-EXPECT: open-redirect


@app.route("/i")
def format_prefix():
    return redirect("{}/home".format(request.args["next"]))  # VH-EXPECT: open-redirect


@app.route("/j")
def host_without_delimiter():
    return requests.get("https://api.example.com" + request.args["p"]).text  # VH-EXPECT: ssrf
