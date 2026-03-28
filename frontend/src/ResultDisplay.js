import React from "react";

const ResultDisplay = ({ result }) => {

  return (
    <div className="result-box">

      <h2>Scan Result</h2>

      <p><b>QR Data:</b> {result.data}</p>
      <p><b>Type:</b> {result.type}</p>

      <p>
        <b>Prediction:</b>{" "}
        <span
          style={{
            color: result.prediction.includes("Phishing") ? "red" : "green",
          }}
        >
          {result.prediction}
        </span>
      </p>

    </div>
  );
};

export default ResultDisplay;