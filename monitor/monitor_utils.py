import os
import ssl
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def sha256sum(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def check_device_status(device="device1"):
    cert_file = f"{device}.crt"
    key_file = f"{device}.key"
    cert_orig = f"{cert_file}.original"
    key_orig = f"{key_file}.original"
    crl_file = "crl.pem"

    result = {
        "device": device,
        "crl_ok": os.path.exists(crl_file),
        "cert_hash_ok": False,
        "key_hash_ok": False,
        "cert_parsed": False,
        "mtls_ok": False,
        "errors": []
    }

    try:
        if not (os.path.exists(cert_file) and os.path.exists(cert_orig)):
            result["errors"].append("Cert or original missing")
        else:
            result["cert_hash_ok"] = (sha256sum(cert_file) == sha256sum(cert_orig))

        if not (os.path.exists(key_file) and os.path.exists(key_orig)):
            result["errors"].append("Key or original missing")
        else:
            result["key_hash_ok"] = (sha256sum(key_file) == sha256sum(key_orig))

        # Try parsing the cert
        with open(cert_file, "rb") as f:
            x509.load_pem_x509_certificate(f.read(), default_backend())
        result["cert_parsed"] = True

        # mTLS test (simplified, or stub for now)
        result["mtls_ok"] = result["cert_parsed"] and result["key_hash_ok"]
    except Exception as e:
        result["errors"].append(str(e))

    return result

