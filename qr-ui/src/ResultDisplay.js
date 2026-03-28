import React from "react";

const Row = ({ label, value }) =>
  value ? (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className="info-value">{value}</span>
    </div>
  ) : null;

const ResultDisplay = ({ result, loading }) => {
  if (loading) {
    return (
      <div className="result-card">
        <div className="verdict-area analyzing">
          <div className="verdict-label">Analyzing</div>
          <div className="verdict-text">Scanning QR code for threats...</div>
          <div className="loading-bar"><div className="loading-fill" /></div>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="result-card idle-card">
        <div className="idle-content">
          <div className="idle-icon" />
          <h3>No QR Code Scanned Yet</h3>
          <p>Start the scanner and point your camera at a QR code to analyze it for phishing threats.</p>
        </div>
      </div>
    );
  }

  const isPhishing = result.prediction?.includes("Phishing");
  const isError = result.type === "ERROR";
  const verdictClass = isPhishing ? "danger" : isError ? "error" : "safe";
  const cleanPrediction = result.prediction?.replace(/[^\x00-\x7F]/g, "").trim();

  return (
    <div className="result-card">
      <div className={`verdict-area ${verdictClass}`}>
        <div className="verdict-label">
          {isPhishing ? "Threat Detected" : isError ? "Error" : "No Threat Detected"}
        </div>
        <div className="verdict-text">{cleanPrediction}</div>
        <div className="verdict-type">QR Type: {result.type}</div>
      </div>

      {(result.domain || result.protocol || result.redirects != null) && (
        <div className="details-section">
          <div className="section-label">URL Analysis</div>
          <div className="info-grid">
            <Row label="Protocol"  value={result.protocol} />
            <Row label="Domain"    value={result.domain} />
            <Row label="Path"      value={result.path} />
            <Row label="Redirects" value={result.redirects != null ? `${result.redirects} redirect(s)` : null} />
            <Row label="Final URL" value={result.final_url !== result.data ? result.final_url : null} />
          </div>
        </div>
      )}

      <div className="details-section">
        <div className="section-label">Raw QR Data</div>
        <div className="raw-data">
          <code>{result.data}</code>
        </div>
      </div>
    </div>
  );
};

export default ResultDisplay;
