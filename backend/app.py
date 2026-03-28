from flask import Flask, request, jsonify
from flask_cors import CORS
from url_preprocessing import preprocess_url
from predict_url import predict_url
from redirect_detector import check_redirect
from upi_analyzer import analyze_upi

app = Flask(__name__)
CORS(app)


def detect_qr_type(data):
    if data.startswith("upi://"):
        return "UPI"
    elif data.startswith("http"):
        return "URL"
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
        "data": data,
        "type": qr_type,
        "prediction": None,
        "risk_level": None,
        "flags": [],
        # URL fields
        "protocol": None,
        "domain": None,
        "path": None,
        "redirects": None,
        "final_url": None,
        # UPI fields
        "upi_id": None,
        "payee_name": None,
        "amount": None,
        "remarks": None,
    }

    if qr_type == "UPI":
        upi_result = analyze_upi(data)
        response["prediction"] = upi_result["prediction"]
        response["risk_level"] = upi_result["risk_level"]
        response["flags"] = upi_result["flags"]
        response["upi_id"] = upi_result["upi_id"]
        response["payee_name"] = upi_result["payee_name"]
        response["amount"] = upi_result["amount"]
        response["remarks"] = upi_result["remarks"]

    elif qr_type == "URL":
        processed = preprocess_url(data)
        if processed:
            response["protocol"] = processed.get("protocol")
            response["domain"] = processed.get("domain")
            response["path"] = processed.get("path") or "/"

        final_url, redirects = check_redirect(data)
        response["final_url"] = final_url
        response["redirects"] = redirects

        ml_prediction = predict_url(final_url)
        is_phishing = "Phishing" in ml_prediction

        # Extra check — payment-related phishing URLs
        payment_keywords = ["pay", "upi", "gpay", "phonepe", "paytm",
                            "payment", "transaction", "wallet", "bank", "transfer"]
        is_payment_url = any(k in final_url.lower() for k in payment_keywords)

        flags = []
        if is_phishing:
            flags.append("ML model flagged this as a phishing URL")
        if redirects > 2:
            flags.append(f"Excessive redirects: {redirects} hops detected")
        if is_payment_url and is_phishing:
            flags.append("Payment-related phishing URL — do not enter card or UPI details")
        if "http://" in final_url and not "https://" in final_url:
            flags.append("Insecure connection — no HTTPS")

        response["flags"] = flags
        response["prediction"] = ml_prediction
        response["risk_level"] = "High Risk" if is_phishing else "Safe"

    else:
        response["prediction"] = f"{qr_type} content"
        response["risk_level"] = "Safe"

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
