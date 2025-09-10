from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template("dashboard.html")

@app.route('/status')
def get_status():
    try:
        with open("data/status.json") as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"error": "No status available"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001)
