import os

from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/download")
def download():
    return send_from_directory(BASE, request.args.get("f"))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    name = secure_filename(f.filename)
    f.save(os.path.join(BASE, name))
    with open(os.path.join(BASE, os.path.basename(request.args["n"]))) as fh:
        return fh.read()
