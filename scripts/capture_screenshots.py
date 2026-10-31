import os
import sys
import time
import subprocess
import urllib.request
import shutil

APP_DIR = r"d:\Network Project\electrical-interference-tool"
sys.path.insert(0, APP_DIR)

from app import app, init_db, seed_two_device_benchmark_data
from sample_data.seed_demo_data import seed_all_demo_data

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not os.path.exists(CHROME_PATH):
    CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

print(f"Using browser: {CHROME_PATH}")

OUTPUT_DIR = os.path.join(APP_DIR, "docs", "images")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 1. Seed demo data
init_db()
s1 = seed_all_demo_data()
s2 = seed_two_device_benchmark_data()
print(f"Seeded sessions: {s1}, {s2}")

# 2. Start Flask in background process
python_exe = sys.executable
flask_proc = subprocess.Popen(
    [python_exe, "app.py"],
    cwd=APP_DIR,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Wait for Flask to be ready
url_base = "http://127.0.0.1:5000"
ready = False
for _ in range(20):
    time.sleep(0.5)
    try:
        with urllib.request.urlopen(f"{url_base}/api/system/status", timeout=1.0) as resp:
            if resp.status == 200:
                ready = True
                break
    except Exception:
        continue

if not ready:
    print("Flask failed to start in time.")
    flask_proc.terminate()
    sys.exit(1)

print("Flask is running and responding.")

PAGES = [
    ("01_overview.png", f"{url_base}/?static_capture=1"),
    ("02_live_dashboard.png", f"{url_base}/dashboard?static_capture=1"),
    ("03_two_device_testing.png", f"{url_base}/two-device-testing?static_capture=1"),
    ("04_device_management.png", f"{url_base}/devices?static_capture=1"),
    ("05_emi_investigation.png", f"{url_base}/investigation?static_capture=1"),
    ("06_network_topology.png", f"{url_base}/topology?static_capture=1"),
    ("07_reports_export.png", f"{url_base}/reports?static_capture=1")
]

for filename, page_url in PAGES:
    out_file = os.path.join(OUTPUT_DIR, filename)
    print(f"Capturing {filename} from {page_url}...")
    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--window-size=1600,1050",
        "--virtual-time-budget=2000",
        f"--screenshot={out_file}",
        page_url
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if os.path.exists(out_file) and os.path.getsize(out_file) > 1000:
        print(f"  [+] Success: {filename} ({os.path.getsize(out_file)} bytes)")
    else:
        print(f"  [-] Failed to capture {filename}")

flask_proc.terminate()
try:
    flask_proc.wait(timeout=2.0)
except Exception:
    flask_proc.kill()

# Also copy to root docs/images
root_images = r"d:\Network Project\docs\images"
os.makedirs(root_images, exist_ok=True)
for filename, _ in PAGES:
    src = os.path.join(OUTPUT_DIR, filename)
    if os.path.exists(src):
        shutil.copy2(src, os.path.join(root_images, filename))

print("All screenshots captured and synchronized.")
