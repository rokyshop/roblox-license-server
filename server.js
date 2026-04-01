import { Hono } from 'hono';
import crypto from 'node:crypto';
import { env } from 'hono/adapter'; // pour accéder aux variables d'environnement / bindings

const app = new Hono();

const SECRET_KEY = "rREd764dJYU7665dsfEF";
const MAX_TIME_DRIFT_SEC = 300;
const MAX_UNAUTHORIZED_IDS = 1000; // non utilisé dans ton code original, je le garde si tu l'utilises ailleurs
const BAN_DURATION_MS = 48 * 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_PER_LICENSE = 30;
const RATE_LIMIT_MAX_PER_IP = 60;

// === Discord Webhook (passé en variable d'environnement pour la sécurité) ===
const DISCORD_WEBHOOK_URL = env("DISCORD_WEBHOOK_URL") || "https://discord.com/api/webhooks/1456714600065007841/eMMvf0l-miTAYraRqZnmxhce4XE6KYZAfCYsHrx122FcV_H30I1iukJ2iSA40fXnvVd0";

// Stockage en mémoire (per-instance Worker)
const licenses = new Map();
const recentNonces = new Map();
const rateLimitIP = new Map();
const rateLimitLicense = new Map();

let lastDiscordNotification = 0;
const DISCORD_COOLDOWN_MS = 3000;

// === Chargement des licenses ===
// Option 1 : depuis KV (recommandé pour production)
// Option 2 : depuis une variable d'environnement JSON (plus simple pour débuter)

async function loadLicenses() {
  try {
    // Exemple avec KV (binding nommé "LICENSES_KV")
    const kvData = await env.LICENSES_KV.get("licenses_data", "text");
    if (!kvData) {
      console.warn("⚠️ Aucune donnée de licenses trouvée dans KV");
      return;
    }

    const sections = kvData.split(/\n\s*\n/);
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
    console.error("❌ Error loading licenses:", err.message);
  }
}

// Charger au démarrage du Worker
loadLicenses();

// Fonction d'alerte Discord
async function sendDiscordAlert(embed) {
  const now = Date.now();
  if (now - lastDiscordNotification < DISCORD_COOLDOWN_MS) {
    console.warn("⚠️ Discord Alert throttled");
    return;
  }
  lastDiscordNotification = now;

  try {
    await fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ embeds: [embed] })
    });
  } catch (err) {
    console.error("❌ Discord Send Error:", err.message);
  }
}

function alert(reason, color = 16711680, extra = "", userid = null, license = null) {
  sendDiscordAlert({
    title: ` ${reason}`,
    color: color,
    description: `**Status:** ACCESS_DENIED\n**Action:** Logged to Terminal`,
    fields: [
      { name: "👤 USER", value: `ID: \`${userid || "N/A"}\`\nLic: \`${license || "N/A"}\``, inline: true },
      { name: "⚖️ ENFORCEMENT", value: `Reason: ${reason}`, inline: true },
      { name: "📦 TRACE", value: `\`\`\`\n${extra}\n\`\`\``, inline: false }
    ],
    footer: { text: "Apex Intelligence Unit" },
    timestamp: new Date().toISOString()
  });
}

// Rate limit helper
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

// Nettoyage des nonces (toutes les minutes)
setInterval(() => {
  const now = Date.now();
  for (const [lic, nonces] of recentNonces.entries()) {
    for (const [n, t] of nonces.entries()) {
      if (now - t > MAX_TIME_DRIFT_SEC * 1000) nonces.delete(n);
    }
    if (!nonces.size) recentNonces.delete(lic);
  }
}, 60 * 1000);

function generateSignature(license, userid, timestamp, nonce) {
  return crypto
    .createHash("sha256")
    .update(SECRET_KEY + `${license}${userid}${timestamp}${nonce}`)
    .digest("hex");
}

// === Route principale ===
app.post('/verify', async (c) => {
  const ip = c.req.header('x-forwarded-for')?.split(',')[0] || 
             c.req.header('cf-connecting-ip') || 
             'unknown';

  const { license, userid, timestamp, nonce } = await c.req.json().catch(() => ({}));

  const now = Math.floor(Date.now() / 1000);
  const nowMs = Date.now();
  const drift = Math.abs(now - Number(timestamp));

  if (!license || !userid || !timestamp || !nonce) {
    console.log(`[AUTH_FAIL] Missing params`);
    return c.json({ status: "invalid", reason: "missing_params" }, 400);
  }

  if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
    console.log(`[RATE_LIMIT] IP throttled`);
    return c.json({ status: "invalid", reason: "rate_limit_ip" }, 429);
  }

  if (!checkRateLimit(rateLimitLicense, license, RATE_LIMIT_MAX_PER_LICENSE, RATE_LIMIT_WINDOW_MS)) {  // j'ai mis 30 comme dans tes constantes
    alert("RATE_LIMIT_LICENSE", 16753920, "", userid, license);
    return c.json({ status: "invalid", reason: "rate_limit_license" }, 429);
  }

  if (drift > MAX_TIME_DRIFT_SEC) {
    alert("TIMESTAMP_EXPIRED", 16711680, "", userid, license);
    return c.json({ status: "invalid", reason: "expired" }, 401);
  }

  // Anti-replay
  const nonceMap = recentNonces.get(license) || new Map();
  if (nonceMap.has(nonce)) {
    alert("REPLAY_ATTACK", 16711680, "", userid, license);
    return c.json({ status: "invalid", reason: "replay" }, 401);
  }
  nonceMap.set(nonce, Date.now());
  recentNonces.set(license, nonceMap);

  if (!licenses.has(license)) {
    alert("UNKNOWN_LICENSE", 16711680, "", userid, license);
    return c.json({ status: "invalid", reason: "unknown_license" }, 404);
  }

  const data = licenses.get(license);

  if (data.banned_until && data.banned_until > nowMs) {
    alert("ATTEMPT_ON_BANNED_LICENSE", 0, "", userid, license);
    return c.json({
      status: "invalid",
      reason: "banned",
      until: data.banned_until
    }, 403);
  }

  const allowed = JSON.parse(data.allowed_ids || "[]").map(Number);
  const uid = Number(userid);

  if (allowed.includes(uid)) {
    data.last_used = Math.floor(nowMs / 1000);
    return c.json({ status: "valid" });
  } else {
    alert("UNAUTHORIZED_USERID", 16711680, `IDs autorized on this keys: ${allowed.length} inscrits`, userid, license);
    return c.json({
      status: "invalid",
      reason: "userid_not_allowed"
    }, 403);
  }
});

app.get('/health', (c) => c.json({ status: "ok" }));

// Export pour Cloudflare Workers
export default app;
