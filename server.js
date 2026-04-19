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

// ============ DISCORD QUEUE SYSTEM ============
// File d'attente + dédoublonnage : évite de spammer Discord (plus de 429)
const discordQueue = [];
const recentAlerts = new Map(); // clé → timestamp du dernier envoi
const DEDUP_WINDOW_MS = 30_000;   // Même alerte (license+raison) max 1x / 30s
const QUEUE_INTERVAL_MS = 1500;   // Envoi max 1 message / 1.5s à Discord
const MAX_QUEUE_SIZE = 50;        // Sécurité anti-explosion mémoire

function sendDiscordAlert(embed, dedupKey) {
  const now = Date.now();

  // 1) Dédoublonnage : si la même alerte a été envoyée récemment, on skip
  if (dedupKey) {
    const last = recentAlerts.get(dedupKey);
    if (last && now - last < DEDUP_WINDOW_MS) {
      return; // silencieusement ignoré, pas de log pour éviter le spam console
    }
    recentAlerts.set(dedupKey, now);
  }

  // 2) Sécurité : si la queue déborde, on drop
  if (discordQueue.length >= MAX_QUEUE_SIZE) {
    return;
  }

  discordQueue.push({ embed, attempts: 0 });
}

function processDiscordQueue() {
  if (discordQueue.length === 0) return;

  const item = discordQueue.shift();
  const data = JSON.stringify({ embeds: [item.embed] });
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
    if (res.statusCode === 429) {
      // Lecture du retry_after pour respecter Discord
      let body = "";
      res.on("data", chunk => body += chunk);
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          const retryAfter = (parsed.retry_after || 5) * 1000;
          console.error(`❌ Discord 429 - retry dans ${retryAfter}ms`);
          // On pause le traitement de la queue
          if (item.attempts < 3) {
            item.attempts++;
            setTimeout(() => discordQueue.unshift(item), retryAfter);
          }
        } catch {
          console.error("❌ Discord 429 - parse fail");
        }
      });
    } else if (res.statusCode >= 400) {
      console.error(`❌ Discord error: ${res.statusCode}`);
    }
  });

  req.on("error", (err) => console.error("❌ Send Error:", err.message));
  req.write(data);
  req.end();
}

// Tick la queue toutes les 1.5s → max ~40 msg/min, Discord autorise 30/min/webhook
setInterval(processDiscordQueue, QUEUE_INTERVAL_MS);

// Nettoyage du dédoublonnage
setInterval(() => {
  const now = Date.now();
  for (const [key, ts] of recentAlerts.entries()) {
    if (now - ts > DEDUP_WINDOW_MS * 2) recentAlerts.delete(key);
  }
}, 60_000);

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
    // On collecte les clés à supprimer AVANT de modifier la map
    const toDelete = [];
    for (const [n, t] of nonces.entries()) {
      if (now - t > MAX_TIME_DRIFT_SEC * 1000) toDelete.push(n);
    }
    toDelete.forEach(n => nonces.delete(n));
    if (!nonces.size) recentNonces.delete(lic);
  }
}
setInterval(cleanNonces, 60_000);

// Nettoyage rate limits (évite de faire grossir les maps à l'infini)
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitIP.entries()) {
    if (now - v.time > RATE_LIMIT_WINDOW_MS * 2) rateLimitIP.delete(k);
  }
  for (const [k, v] of rateLimitLicense.entries()) {
    if (now - v.time > RATE_LIMIT_WINDOW_MS * 2) rateLimitLicense.delete(k);
  }
}, 120_000);

function generateSignature(license, userid, timestamp, nonce) {
  return crypto
    .createHash("sha256")
    .update(SECRET_KEY + `${license}${userid}${timestamp}${nonce}`)
    .digest("hex");
}

// ============ ENDPOINT ============
app.post("/verify", async (req, res) => {
  const ip = (req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress || "unknown").trim();
  const { license, userid, timestamp, nonce } = req.body || {};
  const now = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();

  function alert(reason, color = 16711680, extra = "") {
    // Clé de dédoublonnage : même license + même raison = 1 alerte / 30s
    const dedupKey = `${license || "none"}:${reason}`;
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
    console.log(`[AUTH_FAIL] Missing params from request.`);
    return res.status(400).json({ status: "invalid", reason: "missing_params" });
  }

  // Rate limit IP (silencieux côté Discord pour pas spammer)
  if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
    console.log(`[RATE_LIMIT_IP] ${ip} throttled.`);
    return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
  }

  // Rate limit License (silencieux aussi - sinon Discord explose quand quelqu'un spam)
  if (!checkRateLimit(rateLimitLicense, license, RATE_LIMIT_MAX_PER_LICENSE, RATE_LIMIT_WINDOW_MS)) {
    console.log(`[RATE_LIMIT_LICENSE] ${license} throttled.`);
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
    alert("UNAUTHORIZED_USERID", 16711680, `IDs autorized on this key: ${allowed.length}`);
    return res.status(403).json({
      status: "invalid",
      reason: "userid_not_allowed"
    });
  }
});

app.get("/health", (_, res) => res.json({ status: "ok", queue: discordQueue.length }));

app.listen(3000, () => console.log(" Server running on port 3000"));
