const THREAT_TYPES = [
  { name: "DDoS", desc: "Volumetric or SYN-flood traffic aimed at overwhelming a single destination." },
  { name: "Reconnaissance", desc: "Port scans and host sweeps used to map a network before an attack." },
  { name: "DGA / Suspicious DNS", desc: "High-entropy, machine-generated domain names typical of malware C2 infrastructure." },
  { name: "Command & Control (C2)", desc: "Regular, low-jitter 'beaconing' contact with an external host." },
  { name: "Malware Indicators", desc: "Traffic to known malware/backdoor ports." },
  { name: "Data Exfiltration", desc: "Unusually large outbound transfers or DNS-tunneling patterns." },
];

const STACK = [
  { layer: "Frontend", tech: "React.js" },
  { layer: "Backend", tech: "Node.js + Express.js" },
  { layer: "Database", tech: "MongoDB" },
  { layer: "Packet Analysis", tech: "Scapy (Python)" },
  { layer: "AI / ML", tech: "Python" },
  { layer: "Network Data", tech: "PCAP / IP Traffic" },
  { layer: "Authentication", tech: "JWT" },
  { layer: "Deployment", tech: "Vercel + Render" },
];

export default function ProjectDescription() {
  return (
    <section className="card">
      <h2>AI-Based Detection of Cyber Threats in Unidirectional IP Traffic</h2>
      <p>
        This project analyzes network capture (PCAP) files to detect multiple classes of cyber
        threats from <strong>unidirectional</strong> IP traffic — meaning only one side of each
        network conversation is visible, as is common with span-port / TAP-based monitoring.
        Because return traffic isn't captured, detection relies on volumetric, temporal, and
        content-based signals rather than full bidirectional flow state.
      </p>

      <h3>Threats Detected</h3>
      <ul className="threat-legend">
        {THREAT_TYPES.map((t) => (
          <li key={t.name}>
            <strong>{t.name}:</strong> {t.desc}
          </li>
        ))}
      </ul>

      <h3>Tech Stack</h3>
      <table className="stack-table">
        <tbody>
          {STACK.map((row) => (
            <tr key={row.layer}>
              <td>{row.layer}</td>
              <td>{row.tech}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
