from pathlib import Path

from fastapi import FastAPI

app = FastAPI()
ROOT = Path("/data")


@app.get("/doc")
def doc(name: str):
    p = ROOT / name
    return p.read_text()  # VH-EXPECT: path-traversal
