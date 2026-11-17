import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args["host"]
    os.system("ping -c 1 " + host)  # VH-EXPECT: cmdi
    return "done"


@app.route("/ls")
def ls():
    d = request.values.get("dir")
    out = subprocess.check_output(f"ls {d}", shell=True)  # VH-EXPECT: cmdi
    return out
