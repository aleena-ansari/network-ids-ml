import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load the cleaned data
df = pd.read_csv("data/train_cleaned.csv")

# X = all the feature columns (everything except the labels)
X = df.drop(columns=["label", "attack_type", "difficulty_level"])

# y = what we want to predict
y = df["label"]

# Split into training set (80%) and testing set (20%)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training rows:", X_train.shape[0])
print("Testing rows:", X_test.shape[0])

# Create and train the model
model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
model.fit(X_train, y_train)

print("Model trained!")

# Test it
y_pred = model.predict(X_test)

print("\n--- Results ---")
print(classification_report(y_test, y_pred))
print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred))

# Save the trained model so we can reuse it later (in the backend)
joblib.dump(model, "model.pkl")
print("\nModel saved as model.pkl")