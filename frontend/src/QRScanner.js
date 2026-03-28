import React from "react";
import QrReader from "react-qr-reader";
import axios from "axios";

const QRScanner = ({ setResult }) => {

  const handleScan = async (data) => {
    if (data) {
      console.log("Scanned:", data);

      try {
        const response = await axios.post("http://localhost:5000/predict", {
          qr_data: data,
        });

        setResult(response.data);
      } catch (error) {
        console.error(error);
      }
    }
  };

  const handleError = (err) => {
    console.error(err);
  };

  return (
    <div>
      <QrReader
        delay={300}
        onError={handleError}
        onScan={handleScan}
        style={{ width: "300px" }}
      />
    </div>
  );
};

export default QRScanner;