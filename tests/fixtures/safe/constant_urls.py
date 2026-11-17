import requests
from flask import Flask, request

app = Flask(__name__)
API = "https://api.example.com/v1/items"


@app.route("/items")
def items():
    r = requests.get(API, params={"q": request.args.get("q")}, timeout=5)
    return r.text
