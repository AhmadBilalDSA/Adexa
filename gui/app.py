from flask import Flask, render_template, request
import os
import sys

# Make ADEXA root importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from debugger.gdb_runner import run_gdb
from web_engine.pipeline import analyze_web_request

app = Flask(__name__,
            template_folder="templates",
            static_folder="static")

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/analyze_crash", methods=["POST"])
def crash():
    binary = request.form.get("binary_path")
    crash_output = run_gdb(binary)

    return render_template(
        "index.html",
        crash_output=crash_output,
        last_binary=binary
    )

@app.route("/analyze_web", methods=["POST"])
def web():
    raw_request = request.form.get("raw_request")
    result = analyze_web_request(raw_request)

    return render_template(
        "index.html",
        web_output=result,
        last_request=raw_request
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
