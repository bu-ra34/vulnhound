from flask import Flask, render_template, render_template_string, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template("hello.html", name=name)


@app.route("/hello2")
def hello2():
    return render_template_string("<h1>Hello {{ n }}</h1>", n=escape(request.args.get("n")))
