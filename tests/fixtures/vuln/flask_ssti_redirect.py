from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    tpl = "<h1>Hello " + name + "</h1>"
    return render_template_string(tpl)  # VH-EXPECT: ssti


@app.route("/go")
def go():
    return redirect(request.args.get("next"))  # VH-EXPECT: open-redirect
