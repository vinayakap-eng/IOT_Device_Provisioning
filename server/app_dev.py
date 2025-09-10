from flask import Flask,request,jsonify,send_file
import subprocess
import os

app = Flask(__name__)


@app.route("/enroll", methods=["POST"])
def enroll():
    csr_file = "device.csr"
    raw_crt_file = "device_raw.crt"
    clean_crt_file = "device.crt"

    # Save CSR from client
    with open(csr_file, "wb") as f:
        f.write(request.files["csr"].read())

    # Remove any previous cert files
    for fpath in [raw_crt_file, clean_crt_file]:
        if os.path.exists(fpath):
            os.remove(fpath)

    # Sign certificate using CA
    result = subprocess.run([
        "openssl", "ca",
        "-config", "openssl.cnf",
        "-in", f"../device/{csr_file}",
        "-out", f"../device/{raw_crt_file}",
        "-batch"
    ], capture_output=True, cwd="../ca")  # ✅ run from CA directory

    if result.returncode != 0 or not os.path.exists(raw_crt_file):
        return jsonify({"error": result.stderr.decode()}), 400

    # Clean the certificate using openssl x509
    clean_result = subprocess.run([
        "openssl", "x509",
        "-in", raw_crt_file,
        "-out", clean_crt_file,
        "-outform", "PEM"
    ], capture_output=True)

    if clean_result.returncode != 0:
        return jsonify({"error": clean_result.stderr.decode()}), 500

    return send_file(clean_crt_file, mimetype="application/x-pem-file")

