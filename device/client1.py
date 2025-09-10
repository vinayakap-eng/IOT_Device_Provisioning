import requests
import subprocess
import shutil
import os

# Generate key + CSR
subprocess.run("openssl genrsa -out device.key 2048".split(), check=True)
subprocess.run('openssl req -new -key device.key -out device.csr -subj "/CN=device1"'.split(), check=True)

# Enroll
with open("device.csr", "rb") as f:
    r = requests.post("https://localhost:5000/enroll", files={"csr": f}, verify=False)
with open("device.crt", "wb") as f:
    f.write(r.content)

print("✅ Certificate enrolled")

# Ensure monitor folder exists
monitor_dir = "../monitor"
os.makedirs(monitor_dir, exist_ok=True)

# Save copies for monitoring
shutil.copy("device.crt", "../monitor/device.crt.original")
shutil.copy("device.key", "../monitor/device.key.original")
print("📤 Provisioned cert and key copied for monitor")
