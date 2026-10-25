import base64
import json
from flask import Flask, request

app = Flask(__name__)


@app.route("/prefs")
def prefs():
    blob = base64.b64decode(request.cookies.get("prefs", "") or b"e30=")
    data = json.loads(blob)
    return {"theme": data.get("theme")}
