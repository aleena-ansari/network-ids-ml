
import os
import glob
import json
import hashlib
import pandas as pd
import numpy as np

INPUT_DIR = "data/cicids"
OUTPUT_DIR = "data/cicids_processed"
CHUNK_SIZE = 100_000

os.makedirs(OUTPUT_DIR, exist_ok=True)

TRAIN_FILE = os.path.join(OUTPUT_DIR, "train.csv")
TEST_FILE = os.path.join(OUTPUT_DIR, "test.csv")
REPORT_FILE = os.path.join(OUTPUT_DIR, "preprocessing_report.json")

# Clean old outputs so reruns do not append to previous results.
for path in (TRAIN_FILE, TEST_FILE, REPORT_FILE):
    if os.path.exists(path):
        os.remove(path)

files = sorted(glob.glob(os.path.join(INPUT_DIR, "*.csv")))

if len(files) != 8:
    raise RuntimeError(f"Expected 8 CSV files, found {len(files)}")

# CICIDS2017 files are read using UTF-8 with replacement handling.
# The known replacement character in Web Attack labels is normalized below.
excluded = {
    "label", "flow id", "source ip", "destination ip", "timestamp",
    "is_attack", "source_day"
}

stats = {
    "train": {
        "rows_read": 0, "rows_saved": 0,
        "invalid_rows_removed": 0,
        "duplicates_removed": 0,
        "labels": {}
    },
    "test": {
        "rows_read": 0, "rows_saved": 0,
        "invalid_rows_removed": 0,
        "duplicates_removed": 0,
        "labels": {}
    }
}

# Exact duplicate detection across chunks uses a disk-backed SQLite table.
import sqlite3

db_path = os.path.join(OUTPUT_DIR, "dedup_index.sqlite")
if os.path.exists(db_path):
    os.remove(db_path)

conn = sqlite3.connect(db_path)

conn.execute("""
    CREATE TABLE seen (
        split TEXT NOT NULL,
        digest TEXT NOT NULL,
        PRIMARY KEY (split, digest)
    )
""")

conn.execute("""
    CREATE TABLE cross_split (
        digest TEXT PRIMARY KEY
    )
""")

conn.commit()

reference_columns = None

def normalize_label(series):
    labels = series.astype("string").str.strip()

    # Replace Unicode replacement/dash characters consistently.
    labels = labels.str.replace("\uFFFD", "-", regex=False)
    labels = labels.str.replace("\u2013", "-", regex=False)
    labels = labels.str.replace("\u2014", "-", regex=False)
    labels = labels.str.replace("\u2212", "-", regex=False)

    labels = labels.str.replace(r"\s+", " ", regex=True)

    # Standardize the Web Attack family names.
    labels = labels.str.replace(
        r"(?i)^Web Attack\s*-\s*",
        "Web Attack - ",
        regex=True
    )

    return labels

print("Starting corrected CICIDS2017 preprocessing...")

for file in files:
    filename = os.path.basename(file)
    is_test = filename.lower().startswith("friday")
    split = "test" if is_test else "train"

    output_file = TEST_FILE if is_test else TRAIN_FILE

    print(f"\nProcessing: {filename}")
    print(f"Split: {split}")

    first_output_chunk = not os.path.exists(output_file)

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        low_memory=False,
        encoding="utf-8-sig",
        encoding_errors="replace"
    ):
        chunk.columns = chunk.columns.str.strip()

        label_col = next(
            (c for c in chunk.columns if c.lower() == "label"),
            None
        )

        if label_col is None:
            raise ValueError(f"Label column missing in {filename}")

        if reference_columns is None:
            reference_columns = list(chunk.columns)
        elif list(chunk.columns) != reference_columns:
            raise ValueError(f"Column mismatch in {filename}")

        stats[split]["rows_read"] += len(chunk)

        chunk[label_col] = normalize_label(chunk[label_col])

        # Remove empty labels.
        valid = (
            chunk[label_col].notna()
            & chunk[label_col].ne("")
        )
        chunk = chunk.loc[valid].copy()

        # Convert all model features to numeric.
        feature_columns = [
            c for c in chunk.columns
            if c.lower() not in excluded
            and c != label_col
        ]

        for col in feature_columns:
            chunk[col] = pd.to_numeric(
                chunk[col], errors="coerce"
            )

        chunk[feature_columns] = (
            chunk[feature_columns]
            .replace([np.inf, -np.inf], np.nan)
        )

        before_invalid = len(chunk)
        chunk = chunk.dropna(subset=feature_columns)
        stats[split]["invalid_rows_removed"] += (
            before_invalid - len(chunk)
        )

        # Create binary target.
        chunk["is_attack"] = (
            chunk[label_col].str.upper() != "BENIGN"
        ).astype("int8")

        chunk["source_day"] = (
            "Friday" if is_test else filename.split("-")[0]
        )

        # Hash all feature values and label to identify exact duplicates.
        # Including the label prevents silently merging conflicting labels.
        hash_frame = chunk[feature_columns + [label_col]].copy()

        hashes = pd.util.hash_pandas_object(
            hash_frame,
            index=False
        ).astype("uint64")

        keep_positions = []
        duplicate_count = 0

        for position, digest_value in enumerate(hashes):
            digest = hashlib.sha256(
                str(int(digest_value)).encode("ascii")
            ).hexdigest()

            exists = conn.execute(
                "SELECT 1 FROM seen WHERE split=? AND digest=?",
                (split, digest)
            ).fetchone()

            if exists:
                duplicate_count += 1
                continue

            conn.execute(
                "INSERT INTO seen(split, digest) VALUES (?, ?)",
                (split, digest)
            )

            # Track matching flows in the opposite split.
            other_split = "train" if split == "test" else "test"

            conn.execute(
                "INSERT OR IGNORE INTO cross_split(digest) "
                "SELECT ? WHERE EXISTS "
                "(SELECT 1 FROM seen WHERE split=? AND digest=?)",
                (digest, other_split, digest)
            )

            keep_positions.append(position)

        conn.commit()

        stats[split]["duplicates_removed"] += duplicate_count

        chunk = chunk.iloc[keep_positions].copy()

        if chunk.empty:
            continue

        stats[split]["rows_saved"] += len(chunk)

        counts = chunk[label_col].value_counts()
        for label, count in counts.items():
            stats[split]["labels"][str(label)] = (
                stats[split]["labels"].get(str(label), 0)
                + int(count)
            )

        chunk.to_csv(
            output_file,
            mode="w" if first_output_chunk else "a",
            header=first_output_chunk,
            index=False
        )

        first_output_chunk = False

        print(
            f"Processed chunk | kept: {len(chunk):,} "
            f"| duplicates removed: {duplicate_count:,}"
        )

    print(f"Finished: {filename}")

cross_split_count = conn.execute(
    "SELECT COUNT(*) FROM cross_split"
).fetchone()[0]

conn.close()

report = {
    "dataset": "CICIDS2017 MachineLearningCSV",
    "training_days": "Monday to Thursday",
    "test_day": "Friday",
    "chunk_size": CHUNK_SIZE,
    "cross_split_matching_hashes": cross_split_count,
    "splits": stats
}

with open(REPORT_FILE, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print("\n" + "=" * 65)
print("CORRECTED PREPROCESSING SUMMARY")
print("=" * 65)

for split in ("train", "test"):
    s = stats[split]

    print(f"\n{split.upper()}")
    print("Rows read:", f"{s['rows_read']:,}")
    print("Rows saved:", f"{s['rows_saved']:,}")
    print("Invalid rows removed:", f"{s['invalid_rows_removed']:,}")
    print("Duplicates removed:", f"{s['duplicates_removed']:,}")
    print("Attack labels:")

    for label, count in sorted(s["labels"].items()):
        print(f"  {label}: {count:,}")

print("\nMatching hashes across train/test:", cross_split_count)
print("\nSaved:")
print(TRAIN_FILE)
print(TEST_FILE)
print(REPORT_FILE)
print("\nPreprocessing completed.")
