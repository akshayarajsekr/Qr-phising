import React from "react";

function stripNonAscii(str) {
  if (!str) return str;
  return str.split("").filter((c) => c.charCodeAt(0) < 128).join("").trim();
}

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
          <p>Start the scanner or upload an image to analyze it for phishing and payment fraud.</p>
        </div>
      </div>
    );
  }

  const isPhishing = result.prediction?.includes("Phishing") || result.prediction?.includes("Fraudulent");
  const isSuspicious = result.prediction?.includes("Suspicious") || result.prediction?.includes("concerns");
  const isError = result.type === "ERROR";

  const verdictClass = isPhishing ? "danger" : isSuspicious ? "warning" : isError ? "error" : "safe";
  const verdictLabel = isPhishing ? "Threat Detected"
    : isSuspicious ? "Caution"
    : isError ? "Error"
    : "No Threat Detected";

  const cleanPrediction = stripNonAscii(result.prediction);
  const isUPI = result.type === "UPI";
  const isURL = result.type === "URL";

  return (
    <div className="result-card">
      <div className={`verdict-area ${verdictClass}`}>
        <div className="verdict-label">{verdictLabel}</div>
        <div className="verdict-text">{cleanPrediction}</div>
        <div className="verdict-type">
          QR Type: {result.type}
          {result.risk_level && (
            <span className={`risk-badge ${verdictClass}`}>{result.risk_level}</span>
          )}
        </div>
      </div>

      {/* Flags / Warnings */}
      {result.flags && result.flags.length > 0 && (
        <div className="details-section">
          <div className="section-label">Risk Indicators</div>
          <ul className="flags-list">
            {result.flags.map((flag, i) => (
              <li key={i} className={`flag-item ${isPhishing ? "flag-danger" : "flag-warning"}`}>
                {flag}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* UPI Payment Details */}
      {isUPI && (
        <div className="details-section">
          <div className="section-label">Payment Details</div>
          <div className="info-grid">
            <Row label="UPI ID"    value={result.upi_id} />
            <Row label="Payee"     value={result.payee_name} />
            <Row label="Amount"    value={result.amount ? `Rs. ${result.amount}` : null} />
            <Row label="Remarks"   value={result.remarks} />
          </div>
          {isPhishing || isSuspicious ? (
            <div className="payment-warning">
              Do not proceed with this payment. This QR code shows signs of fraud.
            </div>
          ) : (
            <div className="payment-safe">
              Always verify the payee name and UPI ID before confirming payment.
            </div>
          )}
        </div>
      )}

      {/* URL Analysis */}
      {isURL && (result.domain || result.protocol) && (
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

      {/* Raw Data */}
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
