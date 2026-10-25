import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/preview")
def preview():
    resp = requests.get(request.args["url"], timeout=5)
    return {"status": resp.status_code, "length": len(resp.content)}
