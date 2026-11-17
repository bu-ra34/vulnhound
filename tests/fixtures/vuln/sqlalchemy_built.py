from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)


@app.route("/s")
def search(session):
    q = request.args["q"]
    session.execute(text(f"select * from t where name = '{q}'"))  # VH-EXPECT: sqli
    session.execute(text("select * from t where name = '%s'" % q).bindparams(x=1))  # VH-EXPECT: sqli
