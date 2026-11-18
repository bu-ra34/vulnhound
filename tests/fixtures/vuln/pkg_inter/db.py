import sqlite3


def run_query(name):
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM t WHERE name = '" + name + "'"
    return conn.execute(sql).fetchall()  # VH-EXPECT: sqli
