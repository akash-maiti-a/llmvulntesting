import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_config():
    cfg = yaml.safe_load(request.data)
    return {"keys": sorted(cfg)}
