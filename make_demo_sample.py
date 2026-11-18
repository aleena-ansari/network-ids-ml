"""Build a small replay file (backend/demo_flows.csv) from the Friday TEST data. Read-only on the dataset."""
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent
cols = list(joblib.load(ROOT / "backend" / "cic_columns.pkl"))
src = ROOT / "data" / "cicids_ready" / "test.csv"
out = ROOT / "backend" / "demo_flows.csv"

dtypes = {c: "float32" for c in cols}
dtypes["Label"] = "str"
df = pd.read_csv(src, usecols=cols + ["Label"], dtype=dtypes)

# A demo mix. NOT the real class proportions; real results come from cic_metrics.json.
TARGET = {"BENIGN": 700, "DDoS": 400, "PortScan": 300, "Bot": 100}
parts = []
for label, n in TARGET.items():
    g = df[df["Label"] == label]
    parts.append(g.sample(n=min(n, len(g)), random_state=42))
demo = pd.concat(parts).sample(frac=1, random_state=42).reset_index(drop=True)
demo.to_csv(out, index=False)
print("saved", out, "| rows:", len(demo), "| size KB:", round(out.stat().st_size / 1024))
print(demo["Label"].value_counts().to_string())