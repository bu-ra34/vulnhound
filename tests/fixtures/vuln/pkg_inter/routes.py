from flask import Flask, request

from pkg_inter.db import run_query
from pkg_inter.shell import run_tool

app = Flask(__name__)


@app.route("/q")
def q():
    return str(run_query(request.args.get("name")))


@app.route("/tool")
def tool():
    return run_tool(request.args["opts"])
