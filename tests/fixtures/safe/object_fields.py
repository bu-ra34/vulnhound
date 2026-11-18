import shlex
import subprocess
import sys

from flask import Flask, request

app = Flask(__name__)


class Runner:
    def __init__(self):
        self.cmd = "ls"
        self.other = shlex.quote(sys.argv[1])

    def set_arg(self, value):
        self.arg = shlex.quote(value)

    def go(self):
        subprocess.call(self.cmd, shell=True)
        subprocess.call("tool " + self.other, shell=True)

    def go_arg(self):
        subprocess.call("tool " + self.arg, shell=True)


@app.route("/r")
def route():
    r = Runner()
    r.set_arg(request.args["a"])
    r.go_arg()
    return "ok"
