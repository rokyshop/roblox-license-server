import express from "express";
import crypto from "crypto";
import https from "https";
import fs from "fs";
const app = express();
app.use(express.json());
const SECRET_KEY = "rREd764dJYU7665dsfEF";
const MAX_TIME_DRIFT_SEC = 300;
const MAX_UNAUTHORIZED_IDS = 3;
const BAN_DURATION_MS = 48 * 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_PER_LICENSE = 30;
const RATE_LIMIT_MAX_PER_IP = 60;

const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1456714600065007841/eMMvf0l-miTAYraRqZnmxhce4XE6KYZAfCYsHrx122FcV_H30I1iukJ2iSA40fXnvVd0";

const licenses = new Map();

function loadLicensesFromFile() {
  try {
    const data = fs.readFileSync("licenses.txt", "utf8");
    const sections = data.split(/\n\s*\n/); 

    sections.forEach(section => {
      const lines = section.split("\n").map(l => l.trim());
      let currentLicense = null;
      let allowedIds = [];

      lines.forEach(line => {
        if (line.startsWith("License:")) {
          currentLicense = line.replace("License:", "").trim();
        } else if (line.startsWith("UserID:")) {
          const id = Number(line.replace("UserID:", "").trim());
          if (!isNaN(id)) allowedIds.push(id);
        }
      });

      if (currentLicense) {
        licenses.set(currentLicense, {
          allowed_ids: JSON.stringify(allowedIds),
          last_used: null,
          unauthorized_attempts: JSON.stringify([]),
          banned_until: null
        });
        console.log(`✅ Loaded : ${currentLicense} (${allowedIds.length} IDs)`);
      }
    });
  } catch (err) {
    console.error("❌ Error :", err.message);
  }
}

loadLicensesFromFile();

function sendDiscordAlert(embed) {
  const data = JSON.stringify({ embeds: [embed] }); 
  const url = new URL(DISCORD_WEBHOOK_URL);
  const options = {
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data)
    }
  };

  const req = https.request(options, (res) => {
    if (res.statusCode !== 204 && res.statusCode !== 200) {
      console.error("❌ Erreur Discord:", res.statusCode);
    }
  });
  req.on("error", (err) => console.error("❌ Erreur envoi:", err.message));
  req.write(data);
  req.end();
}

const recentNonces = new Map();
const rateLimitIP = new Map();
const rateLimitLicense = new Map();

function checkRateLimit(map, key, max, windowMs) {
  const now = Date.now();
  const entry = map.get(key);
  if (!entry || now - entry.time > windowMs) {
    map.set(key, { count: 1, time: now });
    return true;
  }
  if (entry.count >= max) return false;
  entry.count++;
  return true;
}

function cleanNonces() {
  const now = Date.now();
  for (const [lic, nonces] of recentNonces.entries()) {
    for (const [n, t] of nonces.entries()) {
      if (now - t > MAX_TIME_DRIFT_SEC * 1000) nonces.delete(n);
    }
    if (!nonces.size) recentNonces.delete(lic);
  }
}
setInterval(cleanNonces, 60 * 1000);

function generateSignature(license, userid, timestamp, nonce) {
  return crypto
    .createHash("sha256")
    .update(SECRET_KEY + `${license}${userid}${timestamp}${nonce}`)
    .digest("hex");
}

app.post("/verify", async (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
  const { license, userid, timestamp, nonce } = req.body;
  const now = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();
  const drift = Math.abs(now - Number(timestamp));
  const nowDate = new Date().toISOString();

function alert(reason, color = 16711680, extra = "") {
    sendDiscordAlert({
      title: `💠 APEX SECURITY TERMINAL | ${reason}`,
      color: color,
      description: `**Priority Status:** ELEVATED\n**Action:** Client Request Processed`,
      fields: [
        { 
          name: "👤 IDENTIFICATION", 
          value: `**ID:** \`${userid || "N/A"}\`\n**License:** \`${license || "N/A"}\``, 
          inline: true 
        },
        { 
          name: "⚖️ ENFORCEMENT", 
          value: `**Reason:** ${reason}\n**Drift:** ${drift}s`, 
          inline: true 
        },
        { 
          name: "📡 FORENSIC EVIDENCE", 
          value: `\`\`\`\n>> Nonce: ${nonce}\n>> Serv Time: ${now}\n\`\`\n`, 
          inline: false 
        },
        { 
          name: "📦 RAW BODY RECEIVED", 
          value: `\`\`\`\nlicense=${license}\nuserid=${userid}\ntimestamp=${timestamp}\nnonce=${nonce}\n${extra}\n\`\`\``, 
          inline: false 
        }
      ],
      footer: { text: "Apex Intelligence Unit" },
      timestamp: new Date()
    });
  }


  if (!license || !userid || !timestamp || !nonce) {
    alert("MISSING_PARAMS", 16776960); 
    return res.status(400).json({ status: "invalid", reason: "missing_params" });
  }

  if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
    alert("RATE_LIMIT_IP", 16753920); 
    return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
  }

  if (!checkRateLimit(rateLimitLicense, license, 100, RATE_LIMIT_WINDOW_MS)) {
    alert("RATE_LIMIT_LICENSE", 16753920);
    return res.status(429).json({ status: "invalid", reason: "rate_limit_license" });
  }

  if (drift > MAX_TIME_DRIFT_SEC) {
    alert("TIMESTAMP_EXPIRED", 16711680); 
    return res.status(401).json({ status: "invalid", reason: "expired" });
  }

  const nonceMap = recentNonces.get(license) || new Map();
  if (nonceMap.has(nonce)) {
    alert("REPLAY_ATTACK", 16711680);
    return res.status(401).json({ status: "invalid", reason: "replay" });
  }
  nonceMap.set(nonce, Date.now());
  recentNonces.set(license, nonceMap);

  if (!licenses.has(license)) {
    alert("UNKNOWN_LICENSE", 16711680);
    return res.status(404).json({ status: "invalid", reason: "unknown_license" });
  }
  const data = licenses.get(license);

  if (data.banned_until && data.banned_until > nowMs) {
    alert("ATTEMPT_ON_BANNED_LICENSE", 0); 
    return res.status(403).json({
      status: "invalid",
      reason: "banned",
      until: data.banned_until
    });
  }

  const allowed = JSON.parse(data.allowed_ids || "[]").map(Number);
  const uid = Number(userid);

  if (allowed.includes(uid)) {
    data.last_used = Math.floor(nowMs / 1000);
    return res.json({ status: "valid" });
  } else {
    alert("UNAUTHORIZED_USERID", 16711680, `IDs autorisez on this keys: ${allowed.length} inscrits`);
    return res.status(403).json({
      status: "invalid",
      reason: "userid_not_allowed"
    });
  }
});
app.get("/health", (_, res) => res.json({ status: "ok" }));

app.listen(3000, () => console.log(" Server running on port 3000"));
