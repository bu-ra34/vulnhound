import os
import shlex
import sys

from flask import Flask, request

app = Flask(__name__)

target = shlex.quote(sys.argv[1])
fixed = "localhost"


def run_global():
    os.system("ping " + target)
    os.system("ping " + fixed)


@app.route("/c")
def closure():
    name = shlex.quote(request.args["name"])
    constant = "hello"

    def inner():
        os.system("echo " + name)
        os.system("echo " + constant)

    inner()
    return "ok"
