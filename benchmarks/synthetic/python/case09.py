import os
from flask import Flask, request

app = Flask(__name__)


BASE = "/srv/app/docs"


@app.route("/doc")
def doc():
    path = os.path.join(BASE, request.args["f"])
    with open(path) as fh:
        return fh.read()
