import os
import time
import ssl
import socket
import hashlib
import requests
import urllib3
import json
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CA_URL = "https://localhost:5000"

def log_event(level, msg):
    prefix = {
        "info": "ℹ️",
        "ok": "✅",
        "warn": "⚠️",
        "error": "❌",
        "alert": "🚨",
        "success": "🔒",
        "monitor": "🕵️"
    }.get(level, "🔔")
    print(f"{prefix} {msg}")

def fetch_and_parse_logs():
    try:
        r = requests.get(f"{CA_URL}/logs", verify=False)
        entries = r.text.strip().split("\n")
        for entry in entries:
            fields = entry.split("\t")
            if entry.startswith("R"):
                log_event("alert", f"Revoked cert -> {fields}")
            elif entry.startswith("V"):
                log_event("ok", f"Issued cert -> {fields}")
        return entries
    except Exception as e:
        log_event("error", f"Log fetch failed: {e}")

def fetch_crl():
    try:
        r = requests.get(f"{CA_URL}/crl", verify=False)
        with open("crl.pem", "wb") as f:
            f.write(r.content)
        log_event("ok", "CRL updated")
    except Exception as e:
        log_event("error", f"CRL fetch failed: {e}")

def cert_info(cert_path):
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            log_event("info", f"Device CN: {cert.subject.rfc4514_string()}")
            log_event("info", f"Valid From: {cert.not_valid_before_utc}")
            log_event("info", f"Valid To  : {cert.not_valid_after_utc}")
    except Exception as e:
        log_event("error", f"Certificate parse error: {e}")

def compare_file_hashes(current_path, original_path, label):
    try:
        with open(current_path, "rb") as f1, open(original_path, "rb") as f2:
            h1 = hashlib.sha256(f1.read()).hexdigest()
            h2 = hashlib.sha256(f2.read()).hexdigest()
            if h1 == h2:
                log_event("ok", f"{label} integrity verified")
            else:
                log_event("alert", f"{label} MISMATCH! Tampering detected!")
    except FileNotFoundError:
        log_event("error", f"Missing file for comparison: {current_path} or {original_path}")

def test_mtls(cert_path, key_path):
    try:
        context = ssl._create_unverified_context()
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="localhost")
        conn.settimeout(5)
        conn.connect(("localhost", 5000))
        log_event("success", "mTLS handshake successful")
        conn.close()
    except Exception as e:
        log_event("error", f"mTLS connection failed: {e}")

def detect_mitm():
    try:
        r1 = requests.get(CA_URL, verify=False)
        r2 = requests.get(CA_URL, verify=False)
        if r1.content != r2.content:
            log_event("warn", "Possible MITM detected: inconsistent responses")
    except Exception as e:
        log_event("error", f"MITM check failed: {e}")

def verify_device_lifecycle():
    log_event("monitor", "Checking IoT device lifecycle and health")
    fetch_and_parse_logs()
    fetch_crl()
    compare_file_hashes("device.crt", "device.crt.original", "Certificate")
    compare_file_hashes("device.key", "device.key.original", "Private Key")
    cert_info("device.crt")
    test_mtls("device.crt", "device.key")
    detect_mitm()

if __name__ == "__main__":
    while True:
        print("\n====================== MONITORING ======================")
        verify_device_lifecycle()
        time.sleep(15)
status = {
    "certificate_status": cert_ok,  # True/False
    "key_status": key_ok,
    "mtls_status": mtls_ok,
    "mitm_status": mitm_safe,
    "revoked": revoked,
    "cn": cert.subject.rfc4514_string() if cert else "Unavailable",
    "valid_from": str(cert.not_valid_before_utc) if cert else "Unavailable",
    "valid_to": str(cert.not_valid_after_utc) if cert else "Unavailable",
    "last_checked": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
}

#with open("../dashboard/data/status.json", "w") as f:
 #   json.dump(status, f, indent=2)
 # Absolute path to dashboard/data/status.json
dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard", "data")
os.makedirs(dashboard_dir, exist_ok=True)
status_file = os.path.join(dashboard_dir, "status.json")

# Write safely
with open(status_file, "w") as f:
    json.dump(status, f, indent=2)

print(f"✅ Status updated to {status_file}")

