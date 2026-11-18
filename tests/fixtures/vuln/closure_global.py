import os
import sys

from flask import Flask, request

app = Flask(__name__)

target = sys.argv[1]


def run_global():
    os.system("ping " + target)  # VH-EXPECT: cmdi


@app.route("/c")
def closure():
    name = request.args["name"]

    def inner():
        os.system("echo " + name)  # VH-EXPECT: cmdi

    inner()
    return "ok"
