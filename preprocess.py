import pandas as pd

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","attack_type","difficulty_level"
]

df = pd.read_csv("data/train.csv", names=columns)

# Step A: Turn attack_type into a simple binary label first
# "normal" stays normal, everything else becomes "attack"
df["label"] = df["attack_type"].apply(lambda x: "normal" if x == "normal" else "attack")

print(df["label"].value_counts())

# Step B: Convert text columns into numbers (ML models can't read words)
categorical_cols = ["protocol_type", "service", "flag"]
df_encoded = pd.get_dummies(df, columns=categorical_cols)

print(df_encoded.shape)
print(df_encoded.head())

# Step C: Save the cleaned data so we don't have to redo this every time
df_encoded.to_csv("data/train_cleaned.csv", index=False)
print("Saved cleaned file!")