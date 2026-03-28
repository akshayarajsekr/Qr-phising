from flask import Flask, request, jsonify
from predict_url import predict_url

app = Flask(__name__)

def detect_qr_type(data):

    if data.startswith("http"):
        return "URL"
    elif data.startswith("upi://"):
        return "UPI"
    else:
        return "TEXT"


@app.route("/predict", methods=["POST"])
def predict():

    data = request.json["qr_data"]

    qr_type = detect_qr_type(data)

    if qr_type == "URL":
        result = predict_url(data)
    elif qr_type == "UPI":
        result = "✅ Safe Payment QR"
    else:
        result = "Other QR Content"

    return jsonify({
        "data": data,
        "type": qr_type,
        "prediction": result
    })


if __name__ == "__main__":
    app.run(debug=True)