from flask import Flask, request, jsonify
from flask_cors import CORS
from url_preprocessing import preprocess_url
from predict_url import predict_url
from redirect_detector import check_redirect

app = Flask(__name__)
CORS(app)


def detect_qr_type(data):
    if data.startswith("http"):
        return "URL"
    elif data.startswith("upi://"):
        return "UPI"
    elif data.startswith("WIFI:"):
        return "WIFI"
    elif data.startswith("mailto:"):
        return "EMAIL"
    else:
        return "TEXT"


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "QR Phishing Detector API is running"})


@app.route("/predict", methods=["POST"])
def predict():
    body = request.get_json()
    data = body.get("qr_data", "").strip()

    if not data:
        return jsonify({"error": "No QR data provided"}), 400

    qr_type = detect_qr_type(data)
    response = {
        "data": data, "type": qr_type, "prediction": None,
        "protocol": None, "domain": None, "path": None,
        "redirects": None, "final_url": None
    }

    if qr_type == "URL":
        processed = preprocess_url(data)
        if processed:
            response["protocol"] = processed.get("protocol")
            response["domain"] = processed.get("domain")
            response["path"] = processed.get("path") or "/"

        final_url, redirects = check_redirect(data)
        response["final_url"] = final_url
        response["redirects"] = redirects
        response["prediction"] = predict_url(final_url)

    elif qr_type == "UPI":
        response["prediction"] = "Safe Payment QR"
    else:
        response["prediction"] = f"{qr_type} content"

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
