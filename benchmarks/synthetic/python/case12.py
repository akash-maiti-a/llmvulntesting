from urllib.parse import urlparse

import requests
from flask import Flask, request

app = Flask(__name__)


ALLOWED = {"images.example.com", "cdn.example.com"}


@app.route("/preview")
def preview():
    url = request.args["url"]
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        return {"error": "host not allowed"}, 400
    resp = requests.get(url, timeout=5)
    return {"status": resp.status_code, "length": len(resp.content)}
