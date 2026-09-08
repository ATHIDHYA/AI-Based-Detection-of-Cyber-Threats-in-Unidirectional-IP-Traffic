const THREAT_LABELS = {
  ddos: "DDoS",
  recon: "Reconnaissance",
  dga: "DGA / Suspicious DNS",
  c2: "Command & Control (Beaconing)",
  exfiltration: "Data Exfiltration",
  malware: "Malware Indicators",
};

function riskLabel(score) {
  if (score >= 70) return { text: "High Risk", className: "risk-high" };
  if (score >= 35) return { text: "Medium Risk", className: "risk-medium" };
  return { text: "Low Risk", className: "risk-low" };
}

export default function ThreatResults({ result }) {
  if (!result || !result.summary) return null;
  const risk = riskLabel(result.risk_score);

  return (
    <div className="results">
      <div className={`risk-banner ${risk.className}`}>
        <span>Risk Score: {result.risk_score}/100</span>
        <span>{risk.text}</span>
      </div>

      <p className="summary-line">
        {result.summary.packet_count} packets · {result.summary.duration_sec}s ·{" "}
        {result.summary.unique_sources} sources · {result.summary.unique_destinations} destinations
      </p>

      {Object.entries(result.threats).map(([key, findings]) => (
        <div key={key} className="threat-block">
          <h4>
            {THREAT_LABELS[key] || key}
            <span className={findings.length ? "badge badge-alert" : "badge badge-clear"}>
              {findings.length ? findings.length : "none"}
            </span>
          </h4>
          {findings.length > 0 && (
            <ul>
              {findings.map((f, i) => (
                <li key={i}>{JSON.stringify(f)}</li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}
