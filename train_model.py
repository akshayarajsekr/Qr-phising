import pandas as pd
import pickle

from feature_extraction import extract_features

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier


# Load dataset
data = pd.read_csv("dataset.csv")

print("Dataset Loaded Successfully")

# Convert URLs into feature vectors
feature_list = []

for url in data["url"]:
    features = extract_features(url)
    feature_list.append(list(features.values()))

X = pd.DataFrame(feature_list)

# Convert labels to numeric
y = data["label"].map({"benign": 0, "malicious": 1})

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Models to compare
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Decision Tree": DecisionTreeClassifier(),
    "Random Forest": RandomForestClassifier(n_estimators=100)
}

best_model = None
best_accuracy = 0

print("\nModel Accuracy Results\n")

# Train and evaluate models
for name, model in models.items():

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print(name, "Accuracy:", accuracy)

    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model


print("\nBest Model Selected:", best_model)

# Save the best model
pickle.dump(best_model, open("phishing_model.pkl", "wb"))

print("Best Model Saved Successfully")