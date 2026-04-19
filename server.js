import express from "express";
import crypto from "crypto";
import https from "https";
import fs from "fs";
const app = express();
app.use(express.json());

const SECRET_KEY = "rREd764dJYU7665dsfEF";
const MAX_TIME_DRIFT_SEC = 300;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_PER_LICENSE = 30;
const RATE_LIMIT_MAX_PER_IP = 60;

const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1495251729439133696/8zcPtNRO-XeShsah94N7DacuLY946CyH7ALAGQaW4gxltsLuBf_qdUV31lC2AOP9LNjq";

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

// === DISCORD DEBUG VERSION ===
const recentAlerts = new Map();
const DEDUP_WINDOW_MS = 30_000;
let discordBackoffUntil = 0;

function sendDiscordAlert(embed, dedupKey) {
  const now = Date.now();
  if (now < discordBackoffUntil) {
    console.warn(`⚠️ Discord en pause (${Math.round((discordBackoffUntil - now)/1000)}s)`);
    return;
  }
  if (dedupKey) {
    const last = recentAlerts.get(dedupKey);
    if (last && now - last < DEDUP_WINDOW_MS) return;
    recentAlerts.set(dedupKey, now);
  }

  const data = JSON.stringify({ embeds: [embed] });
  const url = new URL(DISCORD_WEBHOOK_URL);
  const options = {
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
      "User-Agent": "LicenseServer/1.0 (+https://github.com/roblox-license)"
    },
    timeout: 10_000
  };

  console.log(`📤 Discord POST -> ${url.hostname}${url.pathname.slice(0, 40)}...`);

  const req = https.request(options, (res) => {
    let body = "";
    res.on("data", c => body += c);
    res.on("end", () => {
      // === DEBUG COMPLET ===
      console.log(`📥 Discord response: HTTP ${res.statusCode}`);
      console.log(`📋 Headers:`, JSON.stringify({
        "retry-after": res.headers["retry-after"],
        "x-ratelimit-global": res.headers["x-ratelimit-global"],
        "x-ratelimit-scope": res.headers["x-ratelimit-scope"],
        "x-ratelimit-remaining": res.headers["x-ratelimit-remaining"],
        "x-ratelimit-reset-after": res.headers["x-ratelimit-reset-after"],
        "via": res.headers["via"],
        "cf-ray": res.headers["cf-ray"],
        "server": res.headers["server"]
      }));
      console.log(`📄 Body: ${body.slice(0, 300)}`);

      if (res.statusCode === 429) {
        let wait = 10_000;
        const h = res.headers["retry-after"];
        if (h) {
          const v = parseFloat(h);
          if (!isNaN(v)) wait = Math.ceil(v * 1000);
        }
        wait = Math.min(wait, 60_000);
        discordBackoffUntil = Date.now() + wait;
        console.error(`❌ Discord 429 - pause ${Math.round(wait/1000)}s`);
      } else if (res.statusCode >= 200 && res.statusCode < 300) {
        console.log(`✅ Discord sent OK`);
      }
    });
  });

  req.on("error", (err) => console.error("❌ Discord error:", err.message));
  req.on("timeout", () => { req.destroy(); console.error("❌ Discord timeout"); });
  req.write(data);
  req.end();
}

setInterval(() => {
  const now = Date.now();
  for (const [k, t] of recentAlerts.entries()) {
    if (now - t > DEDUP_WINDOW_MS * 2) recentAlerts.delete(k);
  }
}, 60_000);

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
    const toDel = [];
    for (const [n, t] of nonces.entries()) {
      if (now - t > MAX_TIME_DRIFT_SEC * 1000) toDel.push(n);
    }
    toDel.forEach(n => nonces.delete(n));
    if (!nonces.size) recentNonces.delete(lic);
  }
}
setInterval(cleanNonces, 60_000);

app.post("/verify", async (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
  const { license, userid, timestamp, nonce } = req.body || {};
  const now = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();
  const drift = Math.abs(now - Number(timestamp));

  function alert(reason, color = 16711680, extra = "") {
    const dedupKey = `${license || "none"}:${reason}:${userid || "none"}`;
    sendDiscordAlert({
      title: ` ${reason}`,
      color: color,
      description: `**Status:** ACCESS_DENIED`,
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
    return res.status(400).json({ status: "invalid", reason: "missing_params" });
  }
  if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
  }
  if (!checkRateLimit(rateLimitLicense, license, 100, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ status: "invalid", reason: "rate_limit_license" });
  }
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
    return res.status(403).json({ status: "invalid", reason: "banned", until: data.banned_until });
  }

  const allowed = JSON.parse(data.allowed_ids || "[]").map(Number);
  const uid = Number(userid);
  if (allowed.includes(uid)) {
    data.last_used = Math.floor(nowMs / 1000);
    return res.json({ status: "valid" });
  } else {
    alert("UNAUTHORIZED_USERID", 16711680, `UserID ${uid} not in ${allowed.length} allowed IDs`);
    return res.status(403).json({ status: "invalid", reason: "userid_not_allowed" });
  }
});

app.get("/health", (_, res) => res.json({
  status: "ok",
  discord_backoff_ms: Math.max(0, discordBackoffUntil - Date.now())
}));

app.get("/test-discord", (_, res) => {
  const ts = Date.now();
  sendDiscordAlert({
    title: "✅ Test Alert",
    color: 3066993,
    description: `Test manuel — ${ts}`,
    timestamp: new Date()
  }, `test:${ts}`);
  res.json({ sent: true, backoff_ms: Math.max(0, discordBackoffUntil - Date.now()) });
});

// Route pour forcer reset du backoff si besoin
app.get("/reset-backoff", (_, res) => {
  discordBackoffUntil = 0;
  res.json({ reset: true });
});

app.listen(3000, () => console.log(" Server running on port 3000"));
