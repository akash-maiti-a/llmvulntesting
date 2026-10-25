import os
from flask import abort
from flask import Flask, request

app = Flask(__name__)


BASE = "/srv/app/docs"


@app.route("/doc")
def doc():
    name = os.path.basename(request.args["f"])
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE + os.sep):
        abort(400)
    with open(path) as fh:
        return fh.read()
