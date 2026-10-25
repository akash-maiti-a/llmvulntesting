import ipaddress
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return {"error": "bad address"}, 400
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return {"output": out.stdout}
