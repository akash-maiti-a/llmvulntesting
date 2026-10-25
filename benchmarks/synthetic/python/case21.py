from urllib.parse import urlparse

from flask import redirect
from flask import Flask, request

app = Flask(__name__)


@app.route("/go")
def go():
    nxt = request.args.get("next", "/")
    if urlparse(nxt).netloc or not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        nxt = "/"
    return redirect(nxt)
