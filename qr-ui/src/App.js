import React, { useState } from "react";
import QRScanner from "./QRScanner";
import ResultDisplay from "./ResultDisplay";
import "./App.css";

function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const handleResult = (data) => {
    setResult(data);
    setHistory((prev) => [data, ...prev].slice(0, 8));
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-brand">
          <div className="header-logo">QR</div>
          <div>
            <h1>QR Code Phishing Detector</h1>
            <p>Real-time AI-powered threat analysis</p>
          </div>
        </div>
        <div className="header-status">
          <span className="status-dot" />
          ML Model Active
        </div>
      </header>

      <main className="app-main">
        <div className="top-section">
          <QRScanner setResult={handleResult} setLoading={setLoading} />
        </div>

        <div className="bottom-section">
          <ResultDisplay result={result} loading={loading} />

          {history.length > 0 && (
            <div className="history-card">
              <div className="section-label">Scan History</div>
              <ul>
                {history.map((item, i) => (
                  <li key={i} className={item.prediction?.includes("Phishing") ? "danger" : "safe"}>
                    <span className="history-type">{item.type}</span>
                    <span className="history-pred">{item.prediction?.replace(/[^\x00-\x7F]/g, "").trim()}</span>
                    <span className="history-data">{item.data}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
