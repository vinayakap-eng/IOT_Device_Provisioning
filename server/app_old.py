#openssl x509 -in device.crt -text -noout
from flask import Flask, request, jsonify, send_file
import subprocess, os
app = Flask(__name__)

@app.route("/enroll", methods=["POST"])
def enroll():
    csr_file = "device.csr"
    crt_file = "device.crt"
    with open(csr_file, "wb") as f:
        f.write(request.files["csr"].read())
 # Make sure the old cert is removed
    if os.path.exists(crt_file):
        os.remove(crt_file)


    cmd = f"openssl ca -config ../ca/openssl.cnf -in {csr_file} -out {crt_file} -batch -outform PEM"
    result = subprocess.run(cmd.split(), capture_output=True)
    if result.returncode != 0 or not os.path.exists(crt_file):
        return jsonify({"error": result.stderr.decode()}), 400
     # Sanity check: ensure valid PEM
    with open(crt_file, "rb") as f:
        content = f.read()
        if b"-----BEGIN CERTIFICATE-----" not in content:
            return jsonify({"error": "Malformed certificate returned"}), 500

    return send_file(crt_file, mimetype="application/x-pem-file")

@app.route("/revoke", methods=["POST"])
def revoke():
    cert = request.form["cert"]
    cmd = f"openssl ca -config ../ca/openssl.cnf -revoke {cert}"
    subprocess.run(cmd.split())
    subprocess.run("openssl ca -config ../ca/openssl.cnf -gencrl -out ../ca/crl/crl.pem".split())
    return "Revoked"

@app.route("/logs", methods=["GET"])
def logs():
    return send_file("../ca/index.txt")

@app.route("/crl", methods=["GET"])
def crl():
    return send_file("../ca/crl/crl.pem")

if __name__ == "__main__":
    app.run(ssl_context=("../ca/certs/ca.crt", "../ca/private/ca.key"))
