import os
import time
import ssl
import socket
import hashlib
import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Suppress HTTPS warnings (dev mode only)
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

def cert_hash(cert_path):
    try:
        with open(cert_path, "rb") as f:
            cert = f.read()
            digest = hashlib.sha256(cert).hexdigest()
            log_event("info", f"Device cert SHA256: {digest}")
    except Exception as e:
        log_event("error", f"Cert hash error: {e}")

def key_file_check(path):
    if not os.path.exists(path):
        log_event("error", "Key file missing")
        return
    size = os.path.getsize(path)
    if size < 1024:
        log_event("warn", "Key file size too small — possible corruption")
    else:
        log_event("ok", "Key file OK")

def test_mtls(cert_path, key_path):
    try:
        context = ssl._create_unverified_context()  # <- FIXED here
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
    cert_hash("device.crt")
    cert_info("device.crt")
    key_file_check("device.key")
    test_mtls("device.crt", "device.key")
    detect_mitm()

if __name__ == "__main__":
    while True:
        print("\n====================== MONITORING ======================")
        verify_device_lifecycle()
        time.sleep(15)

