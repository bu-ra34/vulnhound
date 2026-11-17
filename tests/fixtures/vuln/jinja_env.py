import jinja2
from flask import Flask, request

app = Flask(__name__)
env = jinja2.Environment()


@app.route("/render")
def render():
    src = request.form["template"]
    t = jinja2.Template(src)  # VH-EXPECT: ssti
    t2 = env.from_string(src)  # VH-EXPECT: ssti
    return t.render() + t2.render()
