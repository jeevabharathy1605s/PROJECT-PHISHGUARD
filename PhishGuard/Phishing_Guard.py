import pychrome
import time
import traceback
import os
import json
from plyer import notification
from extract_features_selenium import extract_features
from joblib import load
import pandas as pd

# Load model, scaler, selector
model = load("phishing_stacked_model.pkl")
scaler = load("scaler.pkl")
selector = load("selector.pkl")

# Load whitelist (optional)
whitelist = []
if os.path.exists("whitelist.txt"):
    with open("whitelist.txt", "r") as f:
        whitelist = [line.strip().lower() for line in f.readlines()]

print("🛡️ PhishGuard is running... Watching your Chrome tabs...")

browser = pychrome.Browser(url="http://127.0.0.1:9222")

while True:
    try:
        tabs = browser.list_tab()
        print(f"🌐 Found {len(tabs)} tab(s)")
        for tab in tabs:
            try:
                tab.start()
                
                # Safely get URL
                try:
                    result = tab.call_method("Runtime.evaluate", expression="window.location.href")
                    url = result["result"]["value"]
                except Exception as e:
                    print(f"⚠️ Could not retrieve URL: {e}")
                    tab.stop()
                    continue

                # Skip internal tabs or empty
                if not isinstance(url, str) or url.strip() == "" or url.startswith("chrome://") or url.startswith("devtools://"):
                    print(f"⚠️ Skipped internal or empty tab: {url}")
                    tab.stop()
                    continue

                print(f"\n🔍 Checking: {url}")

                # Skip whitelisted URLs
                if any(w in url.lower() for w in whitelist):
                    print("🟢 Trusted site (whitelisted) — skipping prediction.")
                    tab.stop()
                    continue

                # Extract features
                features = extract_features(url)
                print("✅ Extracted features:", features)

                # Predict
                features_df = pd.DataFrame([features])
                selected = selector.transform(features_df)
                scaled = scaler.transform(selected)
                prediction = model.predict(scaled)[0]

                if prediction == 1:
                    print("🚨 WARNING: This site is flagged as PHISHING!")

                    # Notification
                    notification.notify(
                        title="⚠️ Phishing Alert!",
                        message=f"The site {url} is potentially dangerous.",
                        timeout=5
                    )

                    # Log to file
                    with open("logs.txt", "a") as logf:
                        logf.write(f"{time.ctime()} | {url} | PHISHING\n")

                    # Optional: Close tab
                    try:
                        tab.call_method("Page.close")
                    except Exception as e:
                        print("⚠️ Could not close the tab:", e)

                else:
                    print("✅ This site appears safe.")

                tab.stop()

            except Exception as e:
                print("❌ Error while processing:", e)
                traceback.print_exc()
                try:
                    tab.stop()
                except:
                    pass

        time.sleep(4)

    except Exception as e:
        print("❌ Global error:", e)
        traceback.print_exc()
        time.sleep(5)
