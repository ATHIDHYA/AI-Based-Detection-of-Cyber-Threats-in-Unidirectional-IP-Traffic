const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const ScanResult = require("../models/ScanResult");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});

const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB
  fileFilter: (req, file, cb) => {
    const ok = /\.(pcap|pcapng|cap)$/i.test(file.originalname);
    cb(ok ? null : new Error("Only .pcap/.pcapng/.cap files are allowed"), ok);
  },
});

const PYTHON_BIN = process.env.PYTHON_BIN || "python3";
const ANALYZER_SCRIPT = path.join(__dirname, "..", "..", "pcap-service", "analyze_pcap.py");

router.post("/upload", requireAuth, upload.single("pcap"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No pcap file uploaded" });

  const filePath = req.file.path;
  const args = [ANALYZER_SCRIPT, filePath];
  if (process.env.ML_MODEL_PATH) args.push("--model", process.env.ML_MODEL_PATH);

  const py = spawn(PYTHON_BIN, args);

  let stdout = "";
  let stderr = "";
  py.stdout.on("data", (d) => (stdout += d.toString()));
  py.stderr.on("data", (d) => (stderr += d.toString()));

  // Add timeout to prevent hanging
  const timeout = setTimeout(() => {
    py.kill();
    fs.unlink(filePath, () => {});
    if (!res.headersSent) {
      res.status(408).json({ error: "Analysis timeout - file too large or complex" });
    }
  }, 120000); // 2 minute timeout

  py.on("close", async (code) => {
    clearTimeout(timeout);
    fs.unlink(filePath, () => {});

    if (code !== 0) {
      return res.status(500).json({ error: "Analyzer failed", details: stderr || `exit code ${code}` });
    }

    let parsed;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return res.status(500).json({ error: "Could not parse analyzer output", raw: stdout });
    }

    if (parsed.error) return res.status(422).json({ error: parsed.error });

    try {
      const saved = await ScanResult.create({
        user: req.user.id,
        fileName: req.file.originalname,
        summary: parsed.summary,
        threats: parsed.threats,
        riskScore: parsed.risk_score,
      });
      return res.json({ id: saved._id, fileName: req.file.originalname, ...parsed });
    } catch (dbErr) {
      return res.json({ warning: "Result not saved to DB", dbError: dbErr.message, ...parsed });
    }
  });
});

router.get("/history", requireAuth, async (req, res) => {
  const results = await ScanResult.find({ user: req.user.id }).sort({ createdAt: -1 }).limit(50);
  res.json(results);
});

module.exports = router;
