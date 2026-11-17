import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # VH-EXPECT: deserialization
    return str(obj)


@app.route("/cfg", methods=["POST"])
def cfg():
    return str(yaml.load(request.data))  # VH-EXPECT: deserialization
