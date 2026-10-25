import subprocess
from flask import Flask, request

app = Flask(__name__)


def run_report(fmt):
    return subprocess.check_output("report-gen --format " + fmt, shell=True)


@app.route("/report")
def report():
    return run_report(request.args.get("format", "pdf"))
