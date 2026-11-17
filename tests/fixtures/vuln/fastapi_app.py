import sqlite3

import httpx
from fastapi import FastAPI

app = FastAPI()


@app.get("/items")
async def items(name: str):
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM items WHERE name = '{name}'")  # VH-EXPECT: sqli
    return rows.fetchall()


@app.post("/proxy")
async def proxy(target: str):
    async with httpx.AsyncClient() as client:
        r = await client.get(target)  # VH-EXPECT: ssrf
    return r.text


@app.get("/calc")
def calc(expr: str):
    return eval(expr)  # VH-EXPECT: code-exec
