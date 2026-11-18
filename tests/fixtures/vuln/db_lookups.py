import os

from django.shortcuts import get_object_or_404
from flask import Flask, redirect, request, send_file

from models import Doc

app = Flask(__name__)


@app.route("/a")
def id_used_directly():
    doc = Doc.objects.get(pk=request.args["id"])
    return send_file(request.args["id"])  # VH-EXPECT: path-traversal


@app.route("/b")
def key_stays_tainted_for_sinks():
    name = request.args["name"]
    Doc.objects.get(pk=1)
    return send_file(os.path.join("/srv", name))  # VH-EXPECT: path-traversal


@app.route("/c")
def raw_query_on_manager():
    return Doc.objects.raw("select * from d where n = '%s'" % request.args["n"])  # VH-EXPECT: sqli


@app.route("/d")
def plain_dict_get_is_not_a_lookup():
    cfg = {"next": request.args["next"]}
    return redirect(cfg.get("next"))  # VH-EXPECT: open-redirect


@app.route("/e")
def get_or_404_key_used():
    art = get_object_or_404(Doc, pk=request.args["id"])
    return redirect(request.args["id"])  # VH-EXPECT: open-redirect
