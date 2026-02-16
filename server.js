import express from "express";
import crypto from "crypto";
import https from "https";
import fs from "fs";
const app = express();
app.use(express.json());

// ==========================
// CONFIG
// ==========================
const SECRET_KEY = "rREd764dJYU7665dsfEF";
const MAX_TIME_DRIFT_SEC = 300;
const MAX_UNAUTHORIZED_IDS = 3;
const BAN_DURATION_MS = 48 * 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_PER_LICENSE = 30;
const RATE_LIMIT_MAX_PER_IP = 60;

// 🔔 WEBHOOK DISCORD
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1456714600065007841/eMMvf0l-miTAYraRqZnmxhce4XE6KYZAfCYsHrx122FcV_H30I1iukJ2iSA40fXnvVd0";

// ==========================
// STOCKAGE EN MÉMOIRE (REMPLACE LA DB)
// ==========================
const licenses = new Map();

function loadLicensesFromFile() {
  try {
    const data = fs.readFileSync("licenses.txt", "utf8");
    const sections = data.split(/\n\s*\n/); // Coupe le fichier par bloc (séparés par une ligne vide)

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
        console.log(`✅ Chargée : ${currentLicense} (${allowedIds.length} IDs)`);
      }
    });
  } catch (err) {
    console.error("❌ Erreur lors de la lecture de licenses.txt:", err.message);
  }
}

// Charger les licences au démarrage
loadLicensesFromFile();
// ==========================
// FONCTION WEBHOOK DISCORD (CORRIGÉE)
// ==========================
function sendDiscordAlert(message) {
  const data = JSON.stringify({ content: message });
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
  console.log("📤 Envoi webhook Discord...");
  console.log("🔍 URL:", url.hostname + url.pathname);
  const req = https.request(options, (res) => {
    let responseData = "";
    res.on("data", (chunk) => {
      responseData += chunk;
    });
    res.on("end", () => {
      if (res.statusCode === 204 || res.statusCode === 200) {
        console.log("✅ Webhook Discord envoyé avec succès !");
      } else {
        console.error("❌ Erreur webhook:", res.statusCode);
        console.error("Réponse:", responseData);
      }
    });
  });
  req.on("error", (error) => {
    console.error("❌ Erreur lors de l'envoi:", error.message);
  });
  req.write(data);
  req.end();
}

// ==========================
// UTILS
// ==========================
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

// ==========================
// HMAC (ROBLOX SAFE)
// ==========================
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

  // Fonction d'alerte Discord complète (conservée comme l'originale)
  function alert(reason, extra = "") {
    sendDiscordAlert(
      `🚨 **WARNING — ${reason}**
----------------------------------
📝 License: \`${license}\`
👤 UserID: \`${userid}\`
⏱️ Timestamp received: \`${timestamp}\`
⏱️ Timestamp server: \`${now}\`
📉 Drift: \`${drift} sec\`
📅 Server Date: \`${nowDate}\`
🔑 Nonce: \`${nonce}\`
📦 Body received:
license=${license}
userid=${userid}
timestamp=${timestamp}
nonce=${nonce}
${extra}
----------------------------------`
    );
  }

  // 1. Vérification des paramètres manquants
  if (!license || !userid || !timestamp || !nonce) {
    alert("MISSING_PARAMS");
    return res.status(400).json({ status: "invalid", reason: "missing_params" });
  }

  // 2. Rate Limit (IP & Licence)
  if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
    alert("RATE_LIMIT_IP");
    return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
  }

  // NOTE : Pour 100 personnes, j'ai augmenté virtuellement le seuil de la licence ici
  if (!checkRateLimit(rateLimitLicense, license, 100, RATE_LIMIT_WINDOW_MS)) {
    alert("RATE_LIMIT_LICENSE");
    return res.status(429).json({ status: "invalid", reason: "rate_limit_license" });
  }

  // 3. Sécurité (Drift & Replay)
  if (drift > MAX_TIME_DRIFT_SEC) {
    alert("TIMESTAMP_EXPIRED");
    return res.status(401).json({ status: "invalid", reason: "expired" });
  }

  const nonceMap = recentNonces.get(license) || new Map();
  if (nonceMap.has(nonce)) {
    alert("REPLAY_ATTACK");
    return res.status(401).json({ status: "invalid", reason: "replay" });
  }
  nonceMap.set(nonce, Date.now());
  recentNonces.set(license, nonceMap);

  // 4. Vérification de l'existence de la licence
  if (!licenses.has(license)) {
    alert("UNKNOWN_LICENSE");
    return res.status(404).json({ status: "invalid", reason: "unknown_license" });
  }
  const data = licenses.get(license);

  // 5. Check Ban manuel (si tu décides d'en bannir une toi-même dans le fichier)
  if (data.banned_until && data.banned_until > nowMs) {
    return res.status(403).json({
      status: "invalid",
      reason: "banned",
      until: data.banned_until
    });
  }

  const allowed = JSON.parse(data.allowed_ids || "[]").map(Number);
  const uid = Number(userid);

  // ==========================
  // LOGIQUE DE VALIDATION FINALE
  // ==========================
  if (allowed.includes(uid)) {
    // SUCCESS : L'utilisateur est dans la liste
    data.last_used = Math.floor(nowMs / 1000);
    return res.json({ status: "valid" });
  } else {
    // ÉCHEC : L'utilisateur n'est pas autorisé
    // On envoie l'alerte pour que tu puisses l'ajouter si besoin
    alert("UNAUTHORIZED_USERID", `L'utilisateur ${uid} n'est pas dans la liste des 100 autorisés.`);
    
    // On refuse l'accès SANS bannir la licence pour les 99 autres
    return res.status(403).json({
      status: "invalid",
      reason: "userid_not_allowed"
    });
  }
});
// ==========================
app.get("/health", (_, res) => res.json({ status: "ok" }));

app.listen(3000, () => console.log("🚀 Server running on port 3000"));
