from flask import redirect
from flask import Flask, request

app = Flask(__name__)


@app.route("/go")
def go():
    return redirect(request.args["next"])
