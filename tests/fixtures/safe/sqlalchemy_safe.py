from flask import Flask, request
from sqlalchemy import delete, insert, select, text, update

app = Flask(__name__)


@app.route("/s")
def queries(session, tbl):
    q = request.args["q"]
    session.execute(insert(tbl).values(name=f"{q}"))
    session.execute(select(tbl).where(tbl.c.name == "%" + q + "%"))
    session.execute(update(tbl).where(tbl.c.id == 1).values(note="x" + q))
    session.execute(delete(tbl).where(tbl.c.name == q))
    session.execute(text("select * from t where name like :p").bindparams(p=f"%{q}%"))
    session.execute(text("select * from t where name like :p"), {"p": f"%{q}%"})
    session.execute(tbl.insert().values(name="a" + q))
