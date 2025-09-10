from flask import Flask, render_template
from monitor_utils import check_device_status
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def dashboard():
    status = check_device_status("device1")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template("dashboard.html", status=status, timestamp=timestamp)

if __name__ == "__main__":
    app.run(debug=True, port=5002)

