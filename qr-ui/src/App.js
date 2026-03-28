import React, { useState, useEffect } from "react";
import QRScanner from "./QRScanner";
import ResultDisplay from "./ResultDisplay";
import "./App.css";

function stripNonAscii(str) {
  if (!str) return str;
  return str.split("").filter((c) => c.charCodeAt(0) < 128).join("").trim();
}

function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem("qr_history") || "[]"); }
    catch { return []; }
  });
  const [page, setPage] = useState("scanner");
  const [darkMode, setDarkMode] = useState(() =>
    localStorage.getItem("dark_mode") === "true"
  );

  useEffect(() => {
    document.body.classList.toggle("dark", darkMode);
    localStorage.setItem("dark_mode", darkMode);
  }, [darkMode]);

  const handleResult = (data) => {
    setResult(data);
    setPage("scanner");
    const updated = [{ ...data, scanned_at: new Date().toLocaleString() }, ...history].slice(0, 50);
    setHistory(updated);
    localStorage.setItem("qr_history", JSON.stringify(updated));
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("qr_history");
  };

  const getRiskClass = (item) => {
    const p = item.prediction || "";
    if (p.includes("Phishing") || p.includes("Fraudulent") || p.includes("Scam") || p.includes("Do Not"))
      return "danger";
    if (p.includes("Suspicious") || p.includes("concerns") || p.includes("Verify") ||
        item.risk_level === "Medium Risk" || item.risk_level === "Low Risk")
      return "warning";
    return "safe";
  };

  return (
    <div className={`app ${darkMode ? "dark" : ""}`}>
      <header className="app-header">
        <div className="header-brand">
          <div className="header-logo">QR</div>
          <div>
            <h1>QRSafe</h1>
            <p>Real-time AI-powered threat analysis</p>
          </div>
        </div>
        <div className="header-right">
          <nav className="header-nav">
            <button className={`nav-btn ${page === "scanner" ? "active" : ""}`} onClick={() => setPage("scanner")}>
              Scanner
            </button>
            <button className={`nav-btn ${page === "history" ? "active" : ""}`} onClick={() => setPage("history")}>
              History {history.length > 0 && <span className="nav-badge">{history.length}</span>}
            </button>
          </nav>
          <button className="dark-toggle" onClick={() => setDarkMode(!darkMode)}>
            {darkMode ? "Light" : "Dark"}
          </button>
          <div className="header-status">
            <span className="status-dot" />
            ML Active
          </div>
        </div>
      </header>

      {page === "scanner" && (
        <main className="app-main">
          <div className="top-section">
            <QRScanner setResult={handleResult} setLoading={setLoading} />
          </div>
          <div className="bottom-section">
            <ResultDisplay result={result} loading={loading} />
            {history.length > 0 && (
              <div className="history-card">
                <div className="section-label">Recent Scans</div>
                <ul>
                  {history.slice(0, 5).map((item, i) => (
                    <li key={i} className={getRiskClass(item)} onClick={() => { setResult(item); }}>
                      <span className="history-type">{item.type}</span>
                      <span className="history-pred">{stripNonAscii(item.prediction)}</span>
                      <span className="history-data">{item.data}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </main>
      )}

      {page === "history" && (
        <main className="app-main">
          <div className="history-page">
            <div className="history-page-header">
              <div>
                <h2>Scan History</h2>
                <p>{history.length} total scans stored locally on your device</p>
              </div>
              {history.length > 0 && (
                <button className="btn-clear" onClick={clearHistory}>Clear All</button>
              )}
            </div>

            {history.length === 0 ? (
              <div className="history-empty">
                <div className="idle-icon" />
                <h3>No scan history yet</h3>
                <p>Your scans will appear here after you use the scanner.</p>
              </div>
            ) : (
              <div className="history-list">
                {history.map((item, i) => (
                  <div key={i} className={`history-full-item ${getRiskClass(item)}`}
                    onClick={() => { setResult(item); setPage("scanner"); }}>
                    <div className="history-full-top">
                      <span className={`history-full-badge ${getRiskClass(item)}`}>
                        {item.risk_level || "Safe"}
                      </span>
                      <span className="history-full-type">{item.type}</span>
                      <span className="history-full-time">{item.scanned_at}</span>
                    </div>
                    <div className="history-full-pred">{stripNonAscii(item.prediction)}</div>
                    <div className="history-full-data">{item.data}</div>
                    {item.confidence != null && (
                      <div className="history-confidence">
                        <div className="conf-bar">
                          <div className="conf-fill" style={{ width: `${item.confidence}%`,
                            background: item.confidence > 60 ? "#dc2626" : item.confidence > 30 ? "#f59e0b" : "#16a34a"
                          }} />
                        </div>
                        <span>{item.confidence}% threat confidence</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </main>
      )}
    </div>
  );
}

export default App;
