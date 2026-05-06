import re
import urllib.parse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

# ── Feature extraction ──────────────────────────────────
def extract_features(url: str) -> list:
    try:
        parsed   = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path     or ""
    except Exception:
        return [0] * 12

    return [
        len(url),                                            # 1. URL length
        url.count("."),                                      # 2. Dot count
        url.count("-"),                                      # 3. Hyphen count
        url.count("@"),                                      # 4. @ symbol
        url.count("//"),                                     # 5. Double slash
        1 if re.match(r"\d{1,3}(\.\d{1,3}){3}", hostname) else 0,  # 6. IP in domain
        1 if "https" in url[:8] else 0,                     # 7. HTTPS present
        len(hostname.split(".")) - 1,                        # 8. Subdomain depth
        len(path),                                           # 9. Path length
        1 if any(url.lower().endswith(t) for t in [".xyz",".tk",".ml",".ga",".cf"]) else 0,  # 10. Suspicious TLD
        sum(1 for kw in ["login","verify","secure","account","update","confirm"] if kw in url.lower()),  # 11. Keyword count
        1 if re.search(r"[a-z0-9]+(paypal|apple|microsoft|google|amazon)[a-z0-9]*\.[^.]+\.[a-z]+", url.lower()) else 0,  # 12. Brand spoofing
    ]

# ── Load dataset ────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv("data/phishing.csv")

# Adapt column names to your dataset
# Common column names: 'url', 'label', 'status', 'type'
url_col   = "url"     if "url"    in df.columns else df.columns[0]
label_col = "label"   if "label"  in df.columns else \
            "status"  if "status" in df.columns else df.columns[-1]

df = df[[url_col, label_col]].dropna()
df.columns = ["url", "label"]

# Normalise labels to 0/1
if df["label"].dtype == object:
    df["label"] = df["label"].apply(lambda x: 1 if str(x).lower() in ["phishing","1","bad","malicious"] else 0)

print(f"Dataset: {len(df)} rows | Phishing: {df['label'].sum()} | Safe: {(df['label']==0).sum()}")

# ── Build feature matrix ────────────────────────────────
print("Extracting features (this takes ~30 seconds)...")
X = np.array([extract_features(u) for u in df["url"]])
y = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# ── Train ───────────────────────────────────────────────
print("Training Random Forest...")
clf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# ── Evaluate ────────────────────────────────────────────
y_pred = clf.predict(X_test)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))

# ── Save ────────────────────────────────────────────────
with open("model.pkl", "wb") as f:
    pickle.dump(clf, f)
print("✅ Saved model.pkl")
