import React, { useState } from "react";
import QRScanner from "./QRScanner";
import ResultDisplay from "./ResultDisplay";
import "./App.css";

function App() {
  const [result, setResult] = useState(null);

  return (
    <div className="container">
      <h1>AI QR Phishing Detection</h1>

      <QRScanner setResult={setResult} />

      {result && <ResultDisplay result={result} />}
    </div>
  );
}

export default App;