from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/status")
def status():
    try:
        with open("data/status.json") as f:
            return jsonify(json.load(f))
    except Exception as err:
        return jsonify({"error": f"Status file error: {str(err)}"}), 500

if __name__ == "__main__":
    app.run(port=5001, debug=True)

