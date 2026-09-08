# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

A full-stack web app: log in, upload a `.pcap` file, and get back a
threat report (DDoS, Reconnaissance, DGA/DNS abuse, C2 beaconing,
Data Exfiltration, known-malware-port indicators) with a risk score.

## Architecture

```
frontend/  React (Vite) - login/register, upload UI, project description, results, scan history
backend/   Node.js + Express + MongoDB (Mongoose) + JWT auth
pcap-service/  Python + Scapy - the actual packet analysis & detection logic
```

**Flow:** user uploads pcap in React → Express receives it (multer) →
Express spawns `pcap-service/analyze_pcap.py` as a child process → the
script parses the pcap with Scapy and returns a JSON threat report →
Express saves the report to MongoDB and returns it → React renders it.

## Why "unidirectional" matters here

The capture only shows one side of each conversation (as with a
span-port/TAP setup), so there's no visibility into return traffic —
no completed TCP handshakes, no RTT, no ACK-confirmed delivery. Every
detector in `analyze_pcap.py` is built to work from a single vantage
point instead:
- **DDoS** — packet rate + number of distinct sources hitting one destination.
- **Recon** — a single source touching many distinct destination ports/hosts.
- **DGA** — entropy/length of DNS query labels (no need to see the response).
- **C2 beaconing** — regularity of inter-arrival times to the same external host.
- **Exfiltration** — outbound byte volume to external hosts, or oversized DNS records.

It currently uses rule-based thresholds (`THRESHOLDS` dict in
`analyze_pcap.py`) rather than a trained model, since no labeled
dataset was supplied — see the "Extending to real ML" section below.

## Setup

### 1. Python analysis service
```bash
cd pcap-service
pip install -r requirements.txt
# quick manual test:
python3 analyze_pcap.py /path/to/sample.pcap
```

### 2. Backend
```bash
cd backend
npm install
cp .env.example .env
# edit .env: set MONGO_URI, JWT_SECRET, PYTHON_BIN
npm run dev
```
Requires a running MongoDB instance (local `mongod`, or a free
MongoDB Atlas cluster — put its connection string in `MONGO_URI`).

### 3. Frontend
```bash
cd frontend
npm install
cp .env.example .env
# edit .env if your backend isn't on localhost:5000
npm run dev
```
Open the printed local URL (default `http://localhost:5173`), register
an account, log in, and upload a `.pcap` file.

## Deployment (Vercel + Render)

- **Frontend → Vercel**: deploy the `frontend/` folder as a Vite app.
  Set `VITE_API_BASE_URL` to your Render backend URL.
- **Backend + Python analyzer → Render**: deploy `backend/` as a Web
  Service. Because it spawns a Python subprocess, make sure Python 3
  and the packages in `pcap-service/requirements.txt` are available in
  the same environment (e.g. a Render "Native Environment" build step
  that runs both `npm install` and `pip install -r
  ../pcap-service/requirements.txt`, or a Docker-based Render service
  with both runtimes installed). Set `MONGO_URI`, `JWT_SECRET`,
  `PYTHON_BIN`, and `CLIENT_ORIGIN` (your Vercel URL) as environment
  variables.
- Vercel's own serverless functions aren't a good fit for spawning
  long-running Python subprocesses — that's why the Node backend and
  Python analyzer are deployed together on Render.

## Extending to real ML

The rule-based detectors give you a working demo today, and the `agg`
dict inside `analyze_pcap.py` is effectively your feature source for
training a real classifier later:
1. Run `analyze_pcap.py` over many labeled pcaps (benign + attack —
   e.g. CIC-IDS2017/2018, CTU-13, or your own captures).
2. Turn `agg` into a fixed-length feature vector per flow/capture.
3. Train a classifier (Random Forest / XGBoost are solid defaults for
   this kind of tabular network data).
4. Save it as `model.pkl`, set `ML_MODEL_PATH` in `backend/.env`, and
   fill in `build_feature_vector()` inside `maybe_run_ml_model()`.

## Project structure
```
project/
├── backend/
│   ├── server.js
│   ├── package.json
│   ├── .env.example
│   ├── middleware/auth.js
│   ├── models/{User.js, ScanResult.js}
│   └── routes/{authRoutes.js, pcapRoutes.js}
├── pcap-service/
│   ├── analyze_pcap.py
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── .env.example
│   └── src/
│       ├── main.jsx, App.jsx, api.js, styles.css
│       ├── pages/{Login.jsx, Register.jsx, Dashboard.jsx}
│       └── components/{ProjectDescription.jsx, UploadPcap.jsx, ThreatResults.jsx}
└── README.md
```
# AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic
