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
import glob
import logging
import sys
from django.core.wsgi import get_wsgi_application
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iot_dashboard.settings')
django_project_dir = os.path.join(os.path.dirname(__file__), 'dashboard')
sys.path.append(django_project_dir)
application = get_wsgi_application()

from multi_devices.models import DeviceStatus  # Ensure this import works

# Configure logging
logging.basicConfig(filename='monitor.log', level=logging.INFO)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CA_URL = "https://localhost:5000"

def log_event(level, msg, buffer=None):
    prefix = {
        "info": "ℹ️", "ok": "✅", "warn": "⚠️",
        "error": "❌", "alert": "🚨", "success": "🔒", "monitor": "🕵️"
    }.get(level, "🔔")
    line = f"{prefix} {msg}"
    if buffer is not None:
        buffer.append(line)
    else:
        print(line)
    logging.info(f"{level}: {msg}")

def fetch_and_parse_logs():
    revoked_dict = {}
    try:
        r = requests.get(f"{CA_URL}/logs", verify=False)
        entries = r.text.strip().split("\n")
        for entry in entries:
            fields = entry.split("\t")
            if len(fields) > 5:
                cn = fields[5].split('=')[-1] if '=' in fields[5] else fields[5]
                if entry.startswith("R"):
                    revoked_dict[cn] = True
        return revoked_dict
    except Exception as e:
        log_event("error", f"Log fetch failed: {e}")
        return revoked_dict

def fetch_crl():
    try:
        r = requests.get(f"{CA_URL}/crl", verify=False)
        with open("crl.pem", "wb") as f:
            f.write(r.content)
        log_event("ok", "CRL updated")
    except Exception as e:
        log_event("error", f"CRL fetch failed: {e}")

def compare_file_hashes(file1, file2):
    try:
        with open(file1, "rb") as f1, open(file2, "rb") as f2:
            h1 = hashlib.sha256(f1.read()).hexdigest()
            h2 = hashlib.sha256(f2.read()).hexdigest()
            return h1 == h2
    except FileNotFoundError:
        return None

def cert_info(dev, logs):
    try:
        with open(f"{dev}.crt", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            log_event("info", f"{dev} Device CN: {cert.subject.rfc4514_string()}", buffer=logs)
            log_event("info", f"{dev} Valid From: {cert.not_valid_before_utc}", buffer=logs)
            log_event("info", f"{dev} Valid To  : {cert.not_valid_after_utc}", buffer=logs)
            return cert
    except Exception as e:
        log_event("error", f"{dev} Certificate parse error: {e}", buffer=logs)
        return None

def test_mtls(dev, logs):
    start_time = time.time()
    try:
        if not os.path.exists(f"{dev}.crt") or not os.path.exists(f"{dev}.key"):
            log_event("error", f"{dev} Certificate or key file missing", buffer=logs)
            return False, 0
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ca_file = os.path.join(os.path.dirname(__file__), '..', 'ca', 'certs', 'ca.crt')
        if os.path.exists(ca_file):
            context.load_verify_locations(cafile=ca_file)
        context.load_cert_chain(certfile=f"{dev}.crt", keyfile=f"{dev}.key")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="localhost")
        conn.settimeout(5)
        conn.connect(("localhost", 5000))
        latency = (time.time() - start_time) * 1000
        if not compare_file_hashes(f"{dev}.crt", f"{dev}.crt.original") or not compare_file_hashes(f"{dev}.key", f"{dev}.key.original"):
            log_event("error", f"{dev} mTLS failed: Tampered certificate or key detected", buffer=logs)
            conn.close()
            return False, 0
        log_event("success", f"{dev} mTLS handshake successful (Latency: {latency:.2f}ms)", buffer=logs)
        conn.close()
        return True, latency
    except ssl.SSLError as e:
        log_event("error", f"{dev} mTLS connection failed: {e}", buffer=logs)
        return False, 0
    except Exception as e:
        log_event("error", f"{dev} mTLS connection failed: {e}", buffer=logs)
        return False, 0

def detect_mitm(dev, logs):
    try:
        r1 = requests.get(CA_URL, verify=False)
        r2 = requests.get(CA_URL, verify=False)
        mitm_safe = (r1.content == r2.content)
        if not mitm_safe:
            log_event("warn", f"{dev} Possible MITM detected: inconsistent responses", buffer=logs)
        else:
            log_event("ok", f"{dev} MITM check passed", buffer=logs)
        return mitm_safe
    except Exception as e:
        log_event("error", f"{dev} MITM check failed: {e}", buffer=logs)
        return False

def check_device(dev, revoked_dict):
    logs = []
    dev_status = {}

    print(f"\n=== Checking Device: {dev} ===")

    # Integrity Checks
    cert_result = compare_file_hashes(f"{dev}.crt", f"{dev}.crt.original")
    if cert_result is None:
        log_event("error", f"{dev} Missing Certificate or original file", buffer=logs)
        dev_status["certificate_status"] = False
    elif cert_result:
        log_event("ok", f"{dev} Certificate integrity verified", buffer=logs)
        dev_status["certificate_status"] = True
    else:
        log_event("alert", f"{dev} Certificate MISMATCH! Tampering detected!", buffer=logs)
        dev_status["certificate_status"] = False

    key_result = compare_file_hashes(f"{dev}.key", f"{dev}.key.original")
    if key_result is None:
        log_event("error", f"{dev} Missing Private Key or original file", buffer=logs)
        dev_status["key_status"] = False
    elif key_result:
        log_event("ok", f"{dev} Private Key integrity verified", buffer=logs)
        dev_status["key_status"] = True
    else:
        log_event("alert", f"{dev} Private Key MISMATCH! Tampering detected!", buffer=logs)
        dev_status["key_status"] = False

    # Certificate Info
    cert = cert_info(dev, logs)
    dev_status["cn"] = cert.subject.rfc4514_string() if cert else "Unavailable"
    if cert:
        dev_status["valid_from"] = str(cert.not_valid_before_utc)
        dev_status["valid_to"] = str(cert.not_valid_after_utc)

    # mTLS and MITM
    mtls_ok, latency = test_mtls(dev, logs)
    dev_status["mtls_status"] = mtls_ok
    dev_status["latency"] = latency if mtls_ok else 0

    dev_status["mitm_status"] = detect_mitm(dev, logs)

    # Revocation
    revoked = revoked_dict.get(dev, False)
    dev_status["revoked"] = revoked
    if revoked:
        log_event("alert", f"{dev} Certificate is revoked", buffer=logs)

    # Print grouped logs for device
    for line in logs:
        print(line)

    return dev_status

def write_status(statuses):
    import pytz
    india = pytz.timezone("Asia/Kolkata")
    now = datetime.now(india)
    for dev, data in statuses.items():
        DeviceStatus.objects.update_or_create(
            device=dev,
            defaults={
                'certificate_status': data.get('certificate_status', True),
                'key_status': data.get('key_status', True),
                'mtls_status': data.get('mtls_status', True),
                'mitm_status': data.get('mitm_status', True),
                'revoked': data.get('revoked', False),
                'latency': data.get('latency', 0.0),
                'valid_from': data.get('valid_from') if data.get('valid_from') != "Unavailable" else None,
                'valid_to': data.get('valid_to') if data.get('valid_to') != "Unavailable" else None,
                'last_checked': now
            }
        )
    # Optional: Keep status.json for backup
    dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard", "data")
    os.makedirs(dashboard_dir, exist_ok=True)
    status_file = os.path.join(dashboard_dir, "status.json")
    with open(status_file, "w") as f:
        json.dump(statuses, f, indent=2)
    print(f"✅ Status written to {status_file}")

def verify_device_lifecycle():
    log_event("monitor", "Checking IoT device lifecycle and health")
    fetch_crl()
    revoked_dict = fetch_and_parse_logs()

    crt_files = glob.glob("*.crt")
    devices = [os.path.splitext(file)[0] for file in crt_files if not file.endswith(".original") and file != "ca.crt"]
    if not devices:
        log_event("error", "No devices found in monitor folder.")
        return

    statuses = {}
    # Run sequentially to avoid interleaved output
    for dev in devices:
        statuses[dev] = check_device(dev, revoked_dict)

    write_status(statuses)

if __name__ == "__main__":
    while True:
        print("\n====================== MONITORING ======================")
        verify_device_lifecycle()
        time.sleep(15)