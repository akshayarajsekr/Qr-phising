import React, { useRef, useCallback, useState } from "react";
import Webcam from "react-webcam";
import jsQR from "jsqr";
import axios from "axios";

const QRScanner = ({ setResult, setLoading }) => {
  const webcamRef = useRef(null);
  const intervalRef = useRef(null);
  const fileInputRef = useRef(null);
  const lastScanned = useRef("");
  const [scanning, setScanning] = useState(false);
  const [camError, setCamError] = useState(false);
  const [activeTab, setActiveTab] = useState("camera");
  const [uploadedImage, setUploadedImage] = useState(null);
  const [uploadError, setUploadError] = useState("");

  const sendToBackend = useCallback((data) => {
    setLoading(true);
    axios
      .post(`${process.env.REACT_APP_API_URL}/predict`, { qr_data: data })
      .then((res) => {
        setResult(res.data);
        // fetch domain age separately without blocking
        if (res.data.type === "URL" && res.data.domain) {
          axios
            .post(`${process.env.REACT_APP_API_URL}/domain-age`, { domain: res.data.domain })
            .then((ageRes) => {
              setResult((prev) => ({
                ...prev,
                domain_age_days: ageRes.data.domain_age_days,
              }));
            })
            .catch(() => {});
        }
      })
      .catch(() =>
        setResult({ data: data, type: "ERROR", prediction: "Backend unreachable" })
      )
      .finally(() => setLoading(false));
  }, [setResult, setLoading]);

  // ── Camera scan ──
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
      sendToBackend(code.data);
    }
  }, [sendToBackend]);

  const startScanner = () => {
    lastScanned.current = "";
    setScanning(true);
    intervalRef.current = setInterval(scan, 400);
  };

  const stopScanner = () => {
    setScanning(false);
    clearInterval(intervalRef.current);
  };

  // ── Image upload scan ──
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploadError("");
    setUploadedImage(null);

    const reader = new FileReader();
    reader.onload = (ev) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code && code.data) {
          setUploadedImage(ev.target.result);
          sendToBackend(code.data);
        } else {
          setUploadError("No QR code found in this image. Please try another image.");
        }
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
    e.target.value = "";
  };

  const handleTabSwitch = (tab) => {
    if (tab === "camera" && activeTab !== "camera") {
      stopScanner();
    }
    setActiveTab(tab);
    setUploadError("");
    setUploadedImage(null);
  };

  return (
    <div className="scanner-card">
      <div className="scanner-header">
        <div>
          <h2>QR Code Scanner</h2>
          <p>Use camera or upload an image from your gallery</p>
        </div>
        {activeTab === "camera" && (
          <div className={`cam-status ${scanning ? "active" : "inactive"}`}>
            <span className="cam-status-dot" />
            {scanning ? "Scanning" : "Idle"}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="scanner-tabs">
        <button
          className={`tab-btn ${activeTab === "camera" ? "active" : ""}`}
          onClick={() => handleTabSwitch("camera")}
        >
          Camera
        </button>
        <button
          className={`tab-btn ${activeTab === "upload" ? "active" : ""}`}
          onClick={() => handleTabSwitch("upload")}
        >
          Upload Image
        </button>
      </div>

      {/* Camera tab */}
      {activeTab === "camera" && (
        <>
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
        </>
      )}

      {/* Upload tab */}
      {activeTab === "upload" && (
        <div className="upload-section">
          <div
            className="upload-dropzone"
            onClick={() => fileInputRef.current.click()}
          >
            {uploadedImage ? (
              <img src={uploadedImage} alt="Uploaded QR" className="uploaded-preview" />
            ) : (
              <div className="upload-placeholder">
                <div className="upload-icon" />
                <p>Click to select a QR code image</p>
                <span>Supports JPG, PNG, GIF, WebP</span>
              </div>
            )}
          </div>

          {uploadError && (
            <div className="upload-error">{uploadError}</div>
          )}

          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            style={{ display: "none" }}
          />

          <button
            className="btn-start"
            onClick={() => fileInputRef.current.click()}
            style={{ marginTop: "12px", width: "100%" }}
          >
            {uploadedImage ? "Upload Another Image" : "Select Image from Gallery"}
          </button>
        </div>
      )}
    </div>
  );
};

export default QRScanner;
