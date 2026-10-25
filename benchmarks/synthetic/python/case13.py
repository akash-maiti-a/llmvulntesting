from flask import Flask, request

app = Flask(__name__)


@app.route("/calc", methods=["POST"])
def calc():
    return {"result": eval(request.form["expr"])}
