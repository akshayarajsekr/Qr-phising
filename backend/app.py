from flask import Flask, request, jsonify
from flask_cors import CORS
from url_preprocessing import preprocess_url
from predict_url import predict_url
from redirect_detector import check_redirect
from upi_analyzer import analyze_upi
from wifi_analyzer import analyze_wifi
from email_analyzer import analyze_email
from text_analyzer import analyze_text

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
        # WIFI fields
        "ssid": None,
        "security": None,
        # EMAIL fields
        "email_to": None,
        "email_subject": None,
        # TEXT fields
        "contains_url": False,
        "embedded_url": None,
    }

    # ── UPI ──
    if qr_type == "UPI":
        r = analyze_upi(data)
        response.update({
            "prediction": r["prediction"],
            "risk_level": r["risk_level"],
            "flags": r["flags"],
            "upi_id": r["upi_id"],
            "payee_name": r["payee_name"],
            "amount": r["amount"],
            "remarks": r["remarks"],
        })

    # ── URL ──
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
        if "http://" in final_url and "https://" not in final_url:
            flags.append("Insecure connection — no HTTPS")

        response["flags"] = flags
        response["prediction"] = ml_prediction
        response["risk_level"] = "High Risk" if is_phishing else "Safe"

    # ── WIFI ──
    elif qr_type == "WIFI":
        r = analyze_wifi(data)
        response.update({
            "prediction": r["prediction"],
            "risk_level": r["risk_level"],
            "flags": r["flags"],
            "ssid": r["ssid"],
            "security": r["security"],
        })

    # ── EMAIL ──
    elif qr_type == "EMAIL":
        r = analyze_email(data)
        response.update({
            "prediction": r["prediction"],
            "risk_level": r["risk_level"],
            "flags": r["flags"],
            "email_to": r["to"],
            "email_subject": r["subject"],
        })

    # ── TEXT ──
    else:
        r = analyze_text(data)
        response.update({
            "prediction": r["prediction"],
            "risk_level": r["risk_level"],
            "flags": r["flags"],
            "contains_url": r["contains_url"],
            "embedded_url": r["embedded_url"],
        })

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
