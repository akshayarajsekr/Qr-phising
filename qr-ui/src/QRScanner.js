import React, { useRef, useCallback, useState } from "react";
import Webcam from "react-webcam";
import jsQR from "jsqr";
import axios from "axios";

const QRScanner = ({ setResult, setLoading }) => {
  const webcamRef = useRef(null);
  const intervalRef = useRef(null);
  const lastScanned = useRef("");
  const [scanning, setScanning] = useState(false);
  const [camError, setCamError] = useState(false);

  const scan = useCallback(() => {
    const webcam = webcamRef.current;
    if (!webcam) return;
    const video = webcam.video;
    if (!video || video.readyState !== 4) return;

    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);

    if (code && code.data && code.data !== lastScanned.current) {
      lastScanned.current = code.data;
      setLoading(true);
      axios
        .post(`${process.env.REACT_APP_API_URL}/predict`, { qr_data: code.data })
        .then((res) => setResult(res.data))
        .catch(() =>
          setResult({ data: code.data, type: "ERROR", prediction: "Backend unreachable" })
        )
        .finally(() => setLoading(false));
    }
  }, [setResult, setLoading]);

  const startScanner = () => {
    lastScanned.current = "";
    setScanning(true);
    intervalRef.current = setInterval(scan, 400);
  };

  const stopScanner = () => {
    setScanning(false);
    clearInterval(intervalRef.current);
  };

  return (
    <div className="scanner-card">
      <div className="scanner-header">
        <div>
          <h2>Live QR Scanner</h2>
          <p>Position the QR code within the camera frame</p>
        </div>
        <div className={`cam-status ${scanning ? "active" : "inactive"}`}>
          <span className="cam-status-dot" />
          {scanning ? "Scanning" : "Idle"}
        </div>
      </div>

      <div className="webcam-wrapper">
        {scanning ? (
          <Webcam
            ref={webcamRef}
            audio={false}
            screenshotFormat="image/jpeg"
            videoConstraints={{ facingMode: "environment" }}
            onUserMediaError={() => setCamError(true)}
            className="webcam"
          />
        ) : (
          <div className="webcam-placeholder">
            <div className="cam-placeholder-box">
              <div className="cam-placeholder-icon" />
              <p>{camError ? "Camera access denied" : "Camera is off"}</p>
              <span>{camError ? "Please allow camera permissions in your browser" : "Click Start Scanner to begin"}</span>
            </div>
          </div>
        )}

        {scanning && (
          <div className="scan-overlay">
            <div className="scan-corners"><span /></div>
            <div className="scan-line" />
          </div>
        )}
      </div>

      <div className="scanner-controls">
        <button className="btn-start" onClick={startScanner} disabled={scanning}>
          Start Scanner
        </button>
        <button className="btn-stop" onClick={stopScanner} disabled={!scanning}>
          Stop Scanner
        </button>
      </div>
    </div>
  );
};

export default QRScanner;
