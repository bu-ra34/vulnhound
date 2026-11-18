import os
import zipfile

from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    fname = request.args.get("f")
    return send_file(os.path.join(BASE, fname))  # VH-EXPECT: path-traversal


@app.route("/read")
def read():
    p = request.args["p"]
    with open(p) as fh:  # VH-EXPECT: path-traversal
        return fh.read()


@app.route("/unzip", methods=["POST"])
def unzip():
    up = request.files["archive"]
    z = zipfile.ZipFile(up)
    z.extractall("/srv/unpacked")  # VH-EXPECT: path-traversal
    return "ok"
