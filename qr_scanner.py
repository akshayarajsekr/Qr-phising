import cv2

from url_preprocessing import preprocess_url
from predict_url import predict_url
from redirect_detector import check_redirect


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


detector = cv2.QRCodeDetector()
cap = cv2.VideoCapture(0)

print("Scanning QR Code... Press q to exit")

while True:

    ret, frame = cap.read()

    if not ret:
        break

    data, bbox, _ = detector.detectAndDecode(frame)

    if data:

        print("\nExtracted Data:", data)

        qr_type = detect_qr_type(data)

        print("QR Type:", qr_type)

        if qr_type == "URL":

            processed = preprocess_url(data)

            if processed:

                print("\nProcessed URL Components:")

                for key, value in processed.items():
                    print(key, ":", value)

            final_url, redirects = check_redirect(data)

            print("\nRedirect Analysis")
            print("Original URL:", data)
            print("Final URL:", final_url)
            print("Redirect Count:", redirects)

            result = predict_url(final_url)

            print("\nAI Prediction Result:")
            print(result)

        elif qr_type == "UPI":

            print("UPI Payment QR Detected (GPay / Paytm / PhonePe)")
            print("Result: ✅ Safe Payment QR")

        else:

            print("Other QR Content:", data)

    cv2.imshow("QR Scanner", frame)

    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()