import { useState } from "react";
import { api } from "../api";
import ThreatResults from "./ThreatResults";

export default function UploadPcap({ token, onNewResult }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await api.uploadPcap(file, token);
      setResult(data);
      onNewResult?.(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="card">
      <h2>Upload PCAP for Threat Detection</h2>
      <div className="upload-row">
        <input type="file" accept=".pcap,.pcapng,.cap" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={handleUpload} disabled={!file || loading}>
          {loading ? "Analyzing..." : "Analyze"}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {result && <ThreatResults result={result} />}
    </section>
  );
}
