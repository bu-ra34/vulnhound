import os

from flask import Flask, request

from pkg_helpers.util import make_command

app = Flask(__name__)


@app.route("/convert")
def convert():
    cmd = make_command(request.args["opts"])
    os.system(cmd)  # VH-EXPECT: cmdi
    return "ok"
