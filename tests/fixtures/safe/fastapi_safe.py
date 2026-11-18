import sqlite3

from fastapi import FastAPI

app = FastAPI()


@app.get("/items/{item_id}")
def item(item_id: int):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchall()


@app.get("/search")
def search(q: str):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM items WHERE name = :n", {"n": q}).fetchall()
