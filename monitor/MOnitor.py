import time, requests

def poll_logs():
    r = requests.get("https://localhost:5000/logs", verify="../ca/certs/ca.crt")
    for line in r.text.strip().split("\n"):
        if line.startswith("R"):  # Revoked
            print("⚠️  Alert! Revoked cert detected:", line)

def poll_crl():
    r = requests.get("https://localhost:5000/crl", verify="../ca/certs/ca.crt")
    with open("crl.pem", "wb") as f:
        f.write(r.content)
    print("✅ CRL updated")

if __name__ == "__main__":
    while True:
        print("🕵️ Monitoring logs and CRL...")
        try:
            poll_logs()
            poll_crl()
        except Exception as e:
            print("❌ Monitor error:", e)
        time.sleep(10)
