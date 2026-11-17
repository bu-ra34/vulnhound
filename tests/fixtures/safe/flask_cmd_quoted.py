import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ls")
def ls():
    d = shlex.quote(request.args.get("dir", "."))
    return subprocess.check_output(f"ls {d}", shell=True)


@app.route("/version")
def version():
    return subprocess.check_output(["git", "--version"])
