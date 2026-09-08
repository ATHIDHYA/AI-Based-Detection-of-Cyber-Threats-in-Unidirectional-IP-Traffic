const mongoose = require("mongoose");

const ScanResultSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fileName: { type: String, required: true },
    summary: {
      packet_count: Number,
      duration_sec: Number,
      unique_sources: Number,
      unique_destinations: Number,
    },
    threats: {
      ddos: [mongoose.Schema.Types.Mixed],
      recon: [mongoose.Schema.Types.Mixed],
      dga: [mongoose.Schema.Types.Mixed],
      c2: [mongoose.Schema.Types.Mixed],
      exfiltration: [mongoose.Schema.Types.Mixed],
      malware: [mongoose.Schema.Types.Mixed],
    },
    riskScore: { type: Number, default: 0 },
  },
  { timestamps: true, versionKey: false }
);

module.exports = mongoose.model("ScanResult", ScanResultSchema);
