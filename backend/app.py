from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from url_preprocessing import preprocess_url
from predict_url import predict_url
from redirect_detector import check_redirect
from upi_analyzer import analyze_upi
from wifi_analyzer import analyze_wifi
from email_analyzer import analyze_email
from text_analyzer import analyze_text
from domain_age import check_domain_age

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


def calculate_confidence(flags, is_phishing, redirects, has_https, domain_age_days):
    score = 0
    total = 100

    if is_phishing:
        score += 50
    if not has_https:
        score += 15
    if redirects and redirects > 2:
        score += 15
    if domain_age_days is not None and domain_age_days < 30:
        score += 20
    elif domain_age_days is not None and domain_age_days < 180:
        score += 10
    score += min(len(flags) * 5, 20)

    return min(score, total)


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
        "data": data, "type": qr_type,
        "prediction": None, "risk_level": None,
        "confidence": None, "flags": [],
        "protocol": None, "domain": None, "path": None,
        "redirects": None, "final_url": None,
        "domain_age_days": None,
        "upi_id": None, "payee_name": None, "amount": None, "remarks": None,
        "ssid": None, "security": None,
        "email_to": None, "email_subject": None,
        "contains_url": False, "embedded_url": None,
    }

    # ── UPI ──
    if qr_type == "UPI":
        r = analyze_upi(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence,
            "flags": r["flags"], "upi_id": r["upi_id"],
            "payee_name": r["payee_name"], "amount": r["amount"],
            "remarks": r["remarks"],
        })

    # ── URL ──
    elif qr_type == "URL":
        processed = preprocess_url(data)
        domain = None
        if processed:
            response["protocol"] = processed.get("protocol")
            response["domain"] = processed.get("domain")
            response["path"] = processed.get("path") or "/"
            domain = processed.get("domain", "").split(":")[0]

        with ThreadPoolExecutor(max_workers=3) as pool:
            redirect_future = pool.submit(check_redirect, data)
            ml_future = pool.submit(predict_url, data)
            age_future = pool.submit(check_domain_age, domain) if domain else None

            final_url, redirects = redirect_future.result()
            ml_prediction = ml_future.result()
            domain_age_days, age_risk = age_future.result() if age_future else (None, None)

        response["final_url"] = final_url
        response["redirects"] = redirects
        response["domain_age_days"] = domain_age_days

        is_phishing = "Phishing" in ml_prediction
        has_https = "https://" in final_url
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
        if not has_https:
            flags.append("Insecure connection — no HTTPS")
        if domain_age_days is not None and domain_age_days < 30:
            flags.append(f"Newly registered domain — only {domain_age_days} days old")
        elif domain_age_days is not None and domain_age_days < 180:
            flags.append(f"Relatively new domain — {domain_age_days} days old")

        confidence = calculate_confidence(flags, is_phishing, redirects, has_https, domain_age_days)

        if is_phishing and (not has_https or (domain_age_days and domain_age_days < 30)):
            risk_level = "High Risk"
        elif is_phishing:
            risk_level = "High Risk"
        elif flags:
            risk_level = "Medium Risk"
        else:
            risk_level = "Safe"

        response["flags"] = flags
        response["prediction"] = ml_prediction
        response["risk_level"] = risk_level
        response["confidence"] = confidence

    # ── WIFI ──
    elif qr_type == "WIFI":
        r = analyze_wifi(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence,
            "flags": r["flags"], "ssid": r["ssid"], "security": r["security"],
        })

    # ── EMAIL ──
    elif qr_type == "EMAIL":
        r = analyze_email(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence,
            "flags": r["flags"], "email_to": r["to"], "email_subject": r["subject"],
        })

    # ── TEXT ──
    else:
        r = analyze_text(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence,
            "flags": r["flags"], "contains_url": r["contains_url"],
            "embedded_url": r["embedded_url"],
        })

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
