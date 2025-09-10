import os
import subprocess
import requests
import shutil

DEVICE_NAME = "device8"
KEY_FILE = f"{DEVICE_NAME}.key"
CSR_FILE = f"{DEVICE_NAME}.csr"
CERT_FILE = f"{DEVICE_NAME}.crt"
CA_CERT = "ca.crt"  # optional
ENROLL_URL = "https://localhost:5000/enroll"

MONITOR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../monitor"))

def run(cmd):
    subprocess.run(cmd, check=True)

def generate_key_and_csr():
    print("🔐 Generating key...")
    run(["openssl", "genrsa", "-out", KEY_FILE, "2048"])

    print("📝 Generating CSR...")
    run([
        "openssl", "req", "-new", "-key", KEY_FILE,
        "-out", CSR_FILE,
        "-subj", f"/CN={DEVICE_NAME}"
    ])

def enroll_csr():
    print("📤 Sending CSR to server for enrollment...")
    with open(CSR_FILE, 'rb') as csr_file:
        response = requests.post(
            ENROLL_URL,
            files={"csr": csr_file},
            verify=False  # In production: replace with CA_CERT
        )
    if response.status_code == 200:
        with open(CERT_FILE, 'wb') as f:
            f.write(response.content)
        print("✅ Certificate received and saved.")
    

        # Copy to monitor dir
        print("📁 Copying cert and key to monitor...")
        shutil.copy(CERT_FILE, os.path.join(MONITOR_DIR, CERT_FILE))
        shutil.copy(KEY_FILE, os.path.join(MONITOR_DIR, KEY_FILE))
        print("✅ Files copied to monitor directory.")
        
        # Auto-create original backups in monitor
        orig_cert = os.path.join(MONITOR_DIR, CERT_FILE + ".original")
        orig_key = os.path.join(MONITOR_DIR, KEY_FILE + ".original")
        shutil.copy(os.path.join(MONITOR_DIR, CERT_FILE), orig_cert)
        shutil.copy(os.path.join(MONITOR_DIR, KEY_FILE), orig_key)
        print("📦 Original reference files created automatically.")
    else:
        print(f"❌ Enrollment failed: {response.status_code}")
        print(response.text)

def copy_to_monitor():
    print("📁 Copying cert and key to monitor...")
    shutil.copy(CERT_FILE, os.path.join(MONITOR_DIR, CERT_FILE))
    shutil.copy(KEY_FILE, os.path.join(MONITOR_DIR, KEY_FILE))
    print("✅ Files copied to monitor directory.")

    # Make original backup for tamper detection
    orig_cert = os.path.join(MONITOR_DIR, CERT_FILE + ".original")
    orig_key  = os.path.join(MONITOR_DIR, KEY_FILE + ".original")
    if not os.path.exists(orig_cert):
        shutil.copy(os.path.join(MONITOR_DIR, CERT_FILE), orig_cert)
    if not os.path.exists(orig_key):
        shutil.copy(os.path.join(MONITOR_DIR, KEY_FILE), orig_key)
    print("📦 Original reference files ready.")


def main():
    if not os.path.exists(KEY_FILE) or not os.path.exists(CERT_FILE):
        generate_key_and_csr()
        enroll_csr()
    else:
        print("✅ Certificate already exists. Skipping enrollment.")
        copy_to_monitor()


if __name__ == "__main__":
    main()