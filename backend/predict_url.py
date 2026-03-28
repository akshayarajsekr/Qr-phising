import pickle
from feature_extraction import extract_features

model = pickle.load(open("phishing_model.pkl", "rb"))

def predict_url(url):

    features = extract_features(url)

    feature_values = list(features.values())

    prediction = model.predict([feature_values])

    if prediction[0] == 1:
        return "Phishing URL Detected"
    else:
        return "Safe URL"