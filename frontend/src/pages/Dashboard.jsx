import { useEffect, useState } from "react";
import ProjectDescription from "../components/ProjectDescription";
import UploadPcap from "../components/UploadPcap";
import { api } from "../api";

export default function Dashboard({ token, user, onLogout }) {
  const [history, setHistory] = useState([]);

  const loadHistory = async () => {
    try {
      const data = await api.history(token);
      setHistory(data);
    } catch {
      // ignore — history is a convenience, not critical
    }
  };

  useEffect(() => {
    if (token) {
      loadHistory();
    }
  }, [token]);

  return (
    <div className="dashboard">
      <header className="topbar">
        <span>Signed in as {user?.name}</span>
        <button onClick={onLogout}>Log Out</button>
      </header>

      <ProjectDescription />
      <UploadPcap token={token} onNewResult={loadHistory} />

      <section className="card">
        <h2>Scan History</h2>
        {history.length === 0 ? (
          <p>No scans yet.</p>
        ) : (
          <table className="history-table">
            <thead>
              <tr><th>File</th><th>Risk Score</th><th>Date</th></tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h._id}>
                  <td>{h.fileName}</td>
                  <td>{h.riskScore}</td>
                  <td>{new Date(h.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
