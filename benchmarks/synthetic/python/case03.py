import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    out = subprocess.run(f"nslookup {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout}
