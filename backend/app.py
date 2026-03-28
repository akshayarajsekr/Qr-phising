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


def calculate_confidence(flags, is_phishing, redirects, has_https):
    score = 0
    if is_phishing:
        score += 50
    if not has_https:
        score += 15
    if redirects and redirects > 2:
        score += 15
    score += min(len(flags) * 5, 20)
    return min(score, 95)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "QRSafe API is running"})


# ── Fast domain age endpoint called separately by frontend ──
@app.route("/domain-age", methods=["POST"])
def domain_age():
    body = request.get_json()
    domain = body.get("domain", "").strip()
    if not domain:
        return jsonify({"domain_age_days": None, "age_risk": None})
    age_days, age_risk = check_domain_age(domain)
    return jsonify({"domain_age_days": age_days, "age_risk": age_risk})


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
            "confidence": confidence, "flags": r["flags"],
            "upi_id": r["upi_id"], "payee_name": r["payee_name"],
            "amount": r["amount"], "remarks": r["remarks"],
        })

    # ── URL — redirect + ML in parallel, NO domain age here ──
    elif qr_type == "URL":
        processed = preprocess_url(data)
        domain = None
        if processed:
            response["protocol"] = processed.get("protocol")
            response["domain"] = processed.get("domain")
            response["path"] = processed.get("path") or "/"
            domain = processed.get("domain", "").split(":")[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            redirect_future = pool.submit(check_redirect, data)
            ml_future = pool.submit(predict_url, data)
            final_url, redirects = redirect_future.result()
            ml_prediction = ml_future.result()

        response["final_url"] = final_url
        response["redirects"] = redirects

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

        confidence = calculate_confidence(flags, is_phishing, redirects, has_https)
        response["flags"] = flags
        response["prediction"] = ml_prediction
        response["risk_level"] = "High Risk" if is_phishing else ("Medium Risk" if flags else "Safe")
        response["confidence"] = confidence

    # ── WIFI ──
    elif qr_type == "WIFI":
        r = analyze_wifi(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence, "flags": r["flags"],
            "ssid": r["ssid"], "security": r["security"],
        })

    # ── EMAIL ──
    elif qr_type == "EMAIL":
        r = analyze_email(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence, "flags": r["flags"],
            "email_to": r["to"], "email_subject": r["subject"],
        })

    # ── TEXT ──
    else:
        r = analyze_text(data)
        confidence = min(len(r["flags"]) * 25, 95) if r["flags"] else 5
        response.update({
            "prediction": r["prediction"], "risk_level": r["risk_level"],
            "confidence": confidence, "flags": r["flags"],
            "contains_url": r["contains_url"], "embedded_url": r["embedded_url"],
        })

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
