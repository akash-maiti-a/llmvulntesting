import base64
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/prefs")
def prefs():
    blob = base64.b64decode(request.cookies.get("prefs", ""))
    data = pickle.loads(blob)
    return {"theme": data.get("theme")}
