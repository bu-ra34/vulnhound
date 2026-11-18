import json

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/cfg", methods=["POST"])
def cfg():
    a = yaml.safe_load(request.data)
    b = yaml.load(request.data, Loader=yaml.SafeLoader)
    c = json.loads(request.data)
    return str((a, b, c))
