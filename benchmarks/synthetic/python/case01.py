import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    cur = sqlite3.connect("shop.db").cursor()
    cur.execute(f"SELECT name FROM products WHERE name LIKE '%{term}%'")
    return {"results": [r[0] for r in cur.fetchall()]}
