import express from "express";
import crypto from "crypto";
import https from "https";
import fs from "fs";

const app = express();
app.use(express.json());

// ============ CONFIG ============
const SECRET_KEY = "rREd764dJYU7665dsfEF";
const MAX_TIME_DRIFT_SEC = 300;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_PER_LICENSE = 30;
const RATE_LIMIT_MAX_PER_IP = 60;

const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1456702388164493444/tIFr51HNNsJKzbxxxkvklNePVSWTubPYvy4A4LhN61T8hAtYndF70sUJTy2koWu9zHG_";

// ============ LICENSES ============
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

// ============ DISCORD QUEUE ============
const discordQueue = [];
const recentAlerts = new Map();
const DEDUP_WINDOW_MS = 60_000;
const QUEUE_INTERVAL_MS = 2500;
const MAX_QUEUE_SIZE = 20;
const GLOBAL_BACKOFF_MAX_MS = 60_000;

let globalBackoffUntil = 0;

function sendDiscordAlert(embed, dedupKey) {
  const now = Date.now();

  if (now < globalBackoffUntil) return;

  if (dedupKey) {
    const last = recentAlerts.get(dedupKey);
    if (last && now - last < DEDUP_WINDOW_MS) return;
    recentAlerts.set(dedupKey, now);
  }

  if (discordQueue.length >= MAX_QUEUE_SIZE) return;

  discordQueue.push({ embed, createdAt: now });
}

function processDiscordQueue() {
  const now = Date.now();
  if (now < globalBackoffUntil) return;
  if (discordQueue.length === 0) return;

  const item = discordQueue.shift();

  if (now - item.createdAt > 120_000) return;

  const data = JSON.stringify({ embeds: [item.embed] });
  const url = new URL(DISCORD_WEBHOOK_URL);

  const options = {
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
      "User-Agent": "DiscordBot (licence-server, 1.0)"
    },
    timeout: 10_000
  };

  const req = https.request(options, (res) => {
    let body = "";
    res.on("data", chunk => body += chunk);
    res.on("end", () => {
      if (res.statusCode === 429) {
        let retryAfterMs = 10_000;

        const headerRetry = res.headers["retry-after"];
        if (headerRetry) {
          const v = parseFloat(headerRetry);
          if (!isNaN(v)) retryAfterMs = Math.ceil(v * 1000);
        }

        try {
          const parsed = JSON.parse(body);
          if (parsed.retry_after) {
            retryAfterMs = Math.ceil(parsed.retry_after * 1000);
          }
        } catch {
          if (!headerRetry) retryAfterMs = 30_000;
        }

        retryAfterMs = Math.min(retryAfterMs, GLOBAL_BACKOFF_MAX_MS);
        globalBackoffUntil = Date.now() + retryAfterMs;

        console.error(`❌ Discord 429 - pause ${Math.round(retryAfterMs/1000)}s`);
        return;
      }

      if (res.statusCode >= 400) {
        console.error(`❌ Discord HTTP ${res.statusCode}: ${body.slice(0, 120)}`);
      }
    });
  });

  req.on("error", (err) => console.error("❌ Discord send error:", err.message));
  req.on("timeout", () => {
    req.destroy();
    console.error("❌ Discord timeout");
  });

  req.write(data);
  req.end();
}

setInterval(processDiscordQueue, QUEUE_INTERVAL_MS);

setInterval(() => {
  const now = Date.now();
  for (const [key, ts] of recentAlerts.entries()) {
    if (now - ts > DEDUP_WINDOW_MS * 2) recentAlerts.delete(key);
  }
}, 120_000);

// ============ RATE LIMIT / NONCES ============
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
    const toDelete = [];
    for (const [n, t] of nonces.entries()) {
      if (now - t > MAX_TIME_DRIFT_SEC * 1000) toDelete.push(n);
    }
    toDelete.forEach(n => nonces.delete(n));
    if (!nonces.size) recentNonces.delete(lic);
  }
}
setInterval(cleanNonces, 60_000);

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitIP.entries()) {
    if (now - v.time > RATE_LIMIT_WINDOW_MS * 2) rateLimitIP.delete(k);
  }
  for (const [k, v] of rateLimitLicense.entries()) {
    if (now - v.time > RATE_LIMIT_WINDOW_MS * 2) rateLimitLicense.delete(k);
  }
}, 120_000);

// ============ ENDPOINT ============
app.post("/verify", async (req, res) => {
  const ip = (req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress || "unknown").trim();
  const { license, userid, timestamp, nonce } = req.body || {};
  const now = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();

  function alert(reason, color = 16711680, extra = "") {
    const dedupKey = `${license || "none"}:${reason}:${userid || "none"}`;
    sendDiscordAlert({
      title: ` ${reason}`,
      color: color,
      description: `**Status:** ACCESS_DENIED\n**Action:** Logged to Terminal`,
      fields: [
        { name: "👤 USER", value: `ID: \`${userid || "N/A"}\`\nLic: \`${license || "N/A"}\``, inline: true },
        { name: "⚖️ ENFORCEMENT", value: `Reason: ${reason}`, inline: true },
        { name: "📦 TRACE", value: `\`\`\`\n${extra || "—"}\n\`\`\``, inline: false }
      ],
      footer: { text: "Apex Intelligence Unit" },
      timestamp: new Date()
    }, dedupKey);
  }

  if (!license || !userid || !timestamp || !nonce) {
    console.log(`[AUTH_FAIL] Missing params.`);
    return res.status(400).json({ status: "invalid", reason: "missing_params" });
  }

  if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
    console.log(`[RATE_LIMIT_IP] ${ip}`);
    return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
  }

  if (!checkRateLimit(rateLimitLicense, license, RATE_LIMIT_MAX_PER_LICENSE, RATE_LIMIT_WINDOW_MS)) {
    console.log(`[RATE_LIMIT_LICENSE] ${license}`);
    return res.status(429).json({ status: "invalid", reason: "rate_limit_license" });
  }

  const drift = Math.abs(now - Number(timestamp));
  if (drift > MAX_TIME_DRIFT_SEC) {
    alert("TIMESTAMP_EXPIRED", 16711680, `drift=${drift}s`);
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
    alert("UNAUTHORIZED_USERID", 16711680, `UserID ${uid} not in ${allowed.length} allowed IDs`);
    return res.status(403).json({
      status: "invalid",
      reason: "userid_not_allowed"
    });
  }
});

app.get("/health", (_, res) => res.json({
  status: "ok",
  queue: discordQueue.length,
  backoff_ms: Math.max(0, globalBackoffUntil - Date.now())
}));

// Route de test — va sur https://ton-url.onrender.com/test-discord
app.get("/test-discord", (_, res) => {
  sendDiscordAlert({
    title: "✅ Test Alert",
    color: 3066993,
    description: "Test manuel depuis /test-discord",
    timestamp: new Date()
  }, `test:${Date.now()}`);
  res.json({
    sent: true,
    queue: discordQueue.length,
    backoff_ms: Math.max(0, globalBackoffUntil - Date.now())
  });
});

app.listen(3000, () => console.log(" Server running on port 3000"));
