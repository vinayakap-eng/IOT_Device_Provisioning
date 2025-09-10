from flask import Flask, request, jsonify, send_file
import subprocess, os

app = Flask(__name__)

# Resolve absolute paths
HERE      = os.path.abspath(os.path.dirname(__file__))
CA_DIR    = os.path.abspath(os.path.join(HERE, '../ca'))
OPENSSL_CNF = os.path.join(CA_DIR, 'openssl.cnf')

@app.route("/enroll", methods=["POST"])
def enroll():
    csr_file       = os.path.join(HERE, "device.csr")
    raw_crt_file   = os.path.join(HERE, "device_raw.crt")
    clean_crt_file = os.path.join(HERE, "device.crt")

    # Save incoming CSR
    with open(csr_file, "wb") as f:
        f.write(request.files["csr"].read())

    # Remove old certs
    for fpath in (raw_crt_file, clean_crt_file):
        if os.path.exists(fpath):
            os.remove(fpath)

    # Sign CSR with CA
    result = subprocess.run([
        "openssl", "ca",
        "-config", OPENSSL_CNF,
        "-in", csr_file,
        "-out", raw_crt_file,
        "-batch"
    ], check=True, cwd=CA_DIR)

    if result.returncode != 0 or not os.path.exists(raw_crt_file):
        return jsonify({"error": result.stderr.decode()}), 400

    # Convert to clean PEM
    clean = subprocess.run([
        "openssl", "x509",
        "-in", raw_crt_file,
        "-out", clean_crt_file,
        "-outform", "PEM"
    ], check=True)

    if clean.returncode != 0:
        return jsonify({"error": clean.stderr.decode()}), 500

    return send_file(clean_crt_file, mimetype="application/x-pem-file")

@app.route('/logs')
def get_logs():
    index_path = os.path.join(CA_DIR, 'index.txt')
    if os.path.exists(index_path):
        with open(index_path, 'r') as f:
            return f.read()
    return "Index file not found", 404

if __name__ == "__main__":
    app.run(ssl_context=(os.path.join(CA_DIR, 'certs/ca.crt'),
                         os.path.join(CA_DIR, 'private/ca.key')))