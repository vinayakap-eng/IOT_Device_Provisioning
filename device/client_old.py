import requests
import subprocess
import os

# Step 1: Generate private key
print("[*] Generating private key...")
subprocess.run(["openssl", "genrsa", "-out", "device.key", "2048"], check=True)

# Step 2: Generate CSR
print("[*] Generating CSR...")
subprocess.run([
    "openssl", "req", "-new",
    "-key", "device.key",
    "-out", "device.csr",
    "-subj", "/CN=device1"
], check=True)

# Step 3: Check if CSR exists
if not os.path.exists("device.csr"):
    print("[!] CSR generation failed. 'device.csr' not found.")
    exit(1)

# Step 4: Enroll with Flask server
print("[*] Sending CSR to server for enrollment...")
try:
    with open("device.csr", "rb") as f:
        r = requests.post("https://localhost:5000/enroll", files={"csr": f}, verify=False)
    
    if r.status_code == 200:
        with open("device.crt", "wb") as f:
            f.write(r.content)
        print("[✔] Certificate enrolled successfully! Saved as 'device.crt'")
    else:
        print(f"[✖] Server returned error: {r.status_code} - {r.text}")
except Exception as e:
    print(f"[!] Failed to contact server: {e}")

