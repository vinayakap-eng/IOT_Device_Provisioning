import os
import subprocess
import requests

DEVICE_NAME = "device1"
KEY_FILE = f"{DEVICE_NAME}.key"
CSR_FILE = f"{DEVICE_NAME}.csr"
CERT_FILE = f"{DEVICE_NAME}.crt"
CA_CERT = "ca.crt"  # optional, for verifying server
ENROLL_URL = "https://localhost:5000/enroll"

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
            verify=False  # Disable in test; use CA_CERT in production
        )
    if response.status_code == 200:
        with open(CERT_FILE, 'wb') as f:
            f.write(response.content)
        print("✅ Certificate received and saved.")
    else:
        print(f"❌ Enrollment failed: {response.status_code}")
        print(response.text)

def main():
    if not os.path.exists(KEY_FILE) or not os.path.exists(CERT_FILE):
        generate_key_and_csr()
        enroll_csr()
    else:
        print("✅ Certificate already exists. Skipping enrollment.")

    # ⬇️ Your secure communication code using CERT_FILE + KEY_FILE goes here
    # Example: MQTT/mTLS/HTTPS with client cert

if __name__ == "__main__":
    main()

