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

const ConfidenceBar = ({ confidence, verdictClass }) => {
  if (confidence == null) return null;
  const color = confidence > 60 ? "#dc2626" : confidence > 30 ? "#f59e0b" : "#16a34a";
  return (
    <div className="confidence-section">
      <div className="confidence-label">
        <span>Threat Confidence</span>
        <span style={{ color }}>{confidence}%</span>
      </div>
      <div className="conf-bar">
        <div className="conf-fill" style={{ width: `${confidence}%`, background: color }} />
      </div>
    </div>
  );
};

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
          <p>Start the scanner or upload an image to analyze it for threats.</p>
        </div>
      </div>
    );
  }

  const isPhishing = result.prediction?.includes("Phishing") ||
    result.prediction?.includes("Fraudulent") ||
    result.prediction?.includes("Scam") ||
    result.prediction?.includes("Do Not");

  const isSuspicious = result.prediction?.includes("concerns") ||
    result.prediction?.includes("Verify") ||
    result.risk_level === "Medium Risk" ||
    result.risk_level === "Low Risk";

  const isError = result.type === "ERROR";
  const verdictClass = isPhishing ? "danger" : isSuspicious ? "warning" : isError ? "error" : "safe";
  const verdictLabel = isPhishing ? "Threat Detected" : isSuspicious ? "Caution" : isError ? "Error" : "No Threat Detected";
  const cleanPrediction = stripNonAscii(result.prediction);

  const domainAgeText = result.domain_age_days != null
    ? result.domain_age_days < 1 ? "Registered today"
    : result.domain_age_days === 1 ? "1 day old"
    : `${result.domain_age_days} days old`
    : null;

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

      <ConfidenceBar confidence={result.confidence} verdictClass={verdictClass} />

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

      {result.type === "UPI" && (
        <div className="details-section">
          <div className="section-label">Payment Details</div>
          <div className="info-grid">
            <Row label="UPI ID"  value={result.upi_id} />
            <Row label="Payee"   value={result.payee_name} />
            <Row label="Amount"  value={result.amount ? `Rs. ${result.amount}` : null} />
            <Row label="Remarks" value={result.remarks} />
          </div>
          {isPhishing || isSuspicious ? (
            <div className="payment-warning">Do not proceed with this payment. This QR code shows signs of fraud.</div>
          ) : (
            <div className="payment-safe">Always verify the payee name and UPI ID before confirming payment.</div>
          )}
        </div>
      )}

      {result.type === "URL" && (result.domain || result.protocol) && (
        <div className="details-section">
          <div className="section-label">URL Analysis</div>
          <div className="info-grid">
            <Row label="Protocol"   value={result.protocol} />
            <Row label="Domain"     value={result.domain} />
            <Row label="Path"       value={result.path} />
            <Row label="Domain Age" value={domainAgeText} />
            <Row label="Redirects"  value={result.redirects != null ? `${result.redirects} redirect(s)` : null} />
            <Row label="Final URL"  value={result.final_url !== result.data ? result.final_url : null} />
          </div>
        </div>
      )}

      {result.type === "WIFI" && (
        <div className="details-section">
          <div className="section-label">Network Details</div>
          <div className="info-grid">
            <Row label="Network"  value={result.ssid} />
            <Row label="Security" value={result.security} />
          </div>
          {isPhishing || isSuspicious ? (
            <div className="payment-warning">Do not connect to this network. It may be used to intercept your data.</div>
          ) : (
            <div className="payment-safe">Verify this is a trusted network before connecting.</div>
          )}
        </div>
      )}

      {result.type === "EMAIL" && (
        <div className="details-section">
          <div className="section-label">Email Details</div>
          <div className="info-grid">
            <Row label="To"      value={result.email_to} />
            <Row label="Subject" value={result.email_subject} />
          </div>
          {isPhishing || isSuspicious ? (
            <div className="payment-warning">Do not send this email. It may be a phishing or scam attempt.</div>
          ) : (
            <div className="payment-safe">Verify the recipient address before sending.</div>
          )}
        </div>
      )}

      {result.type === "TEXT" && result.contains_url && (
        <div className="details-section">
          <div className="section-label">Embedded URL Found</div>
          <div className="info-grid">
            <Row label="URL" value={result.embedded_url} />
          </div>
          <div className="payment-warning">This text QR contains a URL. Do not visit it without verifying.</div>
        </div>
      )}

      <div className="details-section">
        <div className="section-label">Raw QR Data</div>
        <div className="raw-data"><code>{result.data}</code></div>
      </div>
    </div>
  );
};

export default ResultDisplay;
