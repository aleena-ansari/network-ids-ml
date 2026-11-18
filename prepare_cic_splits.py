
import os
import hashlib
import pandas as pd

INPUT_DIR = "data/cicids_processed"
OUTPUT_DIR = "data/cicids_ready"

TRAIN_INPUT = os.path.join(INPUT_DIR, "train.csv")
TEST_INPUT = os.path.join(INPUT_DIR, "test.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)

TRAIN_OUTPUT = os.path.join(OUTPUT_DIR, "train.csv")
VAL_OUTPUT = os.path.join(OUTPUT_DIR, "validation.csv")
TEST_OUTPUT = os.path.join(OUTPUT_DIR, "test.csv")

# Remove previous outputs before rebuilding.
for path in [TRAIN_OUTPUT, VAL_OUTPUT, TEST_OUTPUT]:
    if os.path.exists(path):
        os.remove(path)

CHUNK_SIZE = 100_000

print("Preparing CICIDS2017 final splits...")

# 1. Read Friday feature-label hashes.
print("\nStep 1: Indexing Friday test records...")

test_hashes = set()

for chunk in pd.read_csv(TEST_INPUT, chunksize=CHUNK_SIZE):
    feature_cols = [
        c for c in chunk.columns
        if c not in ["Label", "is_attack", "source_day"]
    ]

    values = pd.util.hash_pandas_object(
        chunk[feature_cols + ["Label"]],
        index=False
    )

    test_hashes.update(values.astype(str).tolist())

print("Unique test hashes indexed:", len(test_hashes))

# 2. Remove training records that exactly match Friday records.
print("\nStep 2: Removing cross-split matching records...")

train_rows = 0
removed_cross = 0
train_hashes = set()
first_train = True

for chunk in pd.read_csv(TRAIN_INPUT, chunksize=CHUNK_SIZE):
    feature_cols = [
        c for c in chunk.columns
        if c not in ["Label", "is_attack", "source_day"]
    ]

    hashes = pd.util.hash_pandas_object(
        chunk[feature_cols + ["Label"]],
        index=False
    ).astype(str)

    keep = ~hashes.isin(test_hashes)

    removed_cross += int((~keep).sum())
    chunk = chunk.loc[keep].copy()

    # Track remaining training hashes for validation leakage checks.
    train_hashes.update(
        hashes.loc[keep].tolist()
    )

    if not chunk.empty:
        chunk.to_csv(
            TRAIN_OUTPUT,
            mode="w" if first_train else "a",
            header=first_train,
            index=False
        )
        first_train = False
        train_rows += len(chunk)

if first_train:
    raise RuntimeError("No training records remain.")

print("Training rows retained:", train_rows)
print("Cross-split matching rows removed:", removed_cross)

# 3. Split by source day: Monday-Wednesday training,
# Thursday validation.
print("\nStep 3: Creating validation split...")

validation_rows = 0
first_val = True
first_train = True
final_train_rows = 0

# Rebuild Monday-Wednesday training file separately.
temp_train = os.path.join(OUTPUT_DIR, "train_temp.csv")

if os.path.exists(temp_train):
    os.remove(temp_train)

for chunk in pd.read_csv(TRAIN_OUTPUT, chunksize=CHUNK_SIZE):
    days = chunk["source_day"].astype(str).str.lower()

    validation_mask = days.str.startswith("thursday")
    train_mask = ~validation_mask

    validation_chunk = chunk.loc[validation_mask]
    training_chunk = chunk.loc[train_mask]

    if not validation_chunk.empty:
        validation_chunk.to_csv(
            VAL_OUTPUT,
            mode="w" if first_val else "a",
            header=first_val,
            index=False
        )
        first_val = False
        validation_rows += len(validation_chunk)

    if not training_chunk.empty:
        training_chunk.to_csv(
            temp_train,
            mode="w" if first_train else "a",
            header=first_train,
            index=False
        )
        first_train = False
        final_train_rows += len(training_chunk)

if first_train or first_val:
    raise RuntimeError("Training or validation split is empty.")

os.replace(temp_train, TRAIN_OUTPUT)

# 4. Copy Friday test data unchanged.
print("\nStep 4: Preserving Friday test dataset...")

test_rows = 0
first_test = True

for chunk in pd.read_csv(TEST_INPUT, chunksize=CHUNK_SIZE):
    chunk.to_csv(
        TEST_OUTPUT,
        mode="w" if first_test else "a",
        header=first_test,
        index=False
    )
    first_test = False
    test_rows += len(chunk)

# 5. Report.
print("\n" + "=" * 60)
print("FINAL DATASET SPLIT SUMMARY")
print("=" * 60)

print("Training (Monday-Wednesday):", f"{final_train_rows:,}")
print("Validation (Thursday):", f"{validation_rows:,}")
print("Testing (Friday):", f"{test_rows:,}")

for name, path in [
    ("TRAIN", TRAIN_OUTPUT),
    ("VALIDATION", VAL_OUTPUT),
    ("TEST", TEST_OUTPUT)
]:
    counts = pd.read_csv(
        path, usecols=["Label"]
    )["Label"].value_counts()

    print(f"\n{name} LABEL DISTRIBUTION")
    print(counts.to_string())

print("\nFiles saved in:", OUTPUT_DIR)
print("Dataset splitting completed.")
