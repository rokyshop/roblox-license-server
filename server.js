import express from "express";
import crypto from "crypto";
import pkg from "pg";
import https from "https";  // ← Module natif Node.js

const { Pool } = pkg;

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
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1456702388164493444/tIFr51HNNsJKzbxxxkvklNePVSWTubPYvy4A4LhN61T8hAtYndF70sUJTy2koWu9zHG_";

// PostgreSQL (Render)
const pool = new Pool({
	connectionString: process.env.DATABASE_URL,
	ssl: { rejectUnauthorized: false }
});

// ==========================
// FONCTION WEBHOOK DISCORD (HTTPS NATIF)
// ==========================
function sendDiscordAlert(message) {
	const data = JSON.stringify({ content: message });
	
	const url = new URL(DISCORD_WEBHOOK_URL);
	
	const options = {
		hostname: url.hostname,
		path: url.pathname,
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"Content-Length": data.length
		}
	};

	console.log("📤 Envoi webhook Discord...");
	
	const req = https.request(options, (res) => {
		if (res.statusCode === 204 || res.statusCode === 200) {
			console.log("✅ Webhook Discord envoyé !");
		} else {
			console.error("❌ Erreur webhook:", res.statusCode);
		}
	});

	req.on("error", (error) => {
		console.error("❌ Erreur lors de l'envoi:", error.message);
	});

	req.write(data);
	req.end();
}

// ==========================
// DB INIT
// ==========================
async function initDatabase() {
	await pool.query(`
		CREATE TABLE IF NOT EXISTS licenses (
			license TEXT PRIMARY KEY,
			allowed_ids TEXT,
			last_used BIGINT,
			unauthorized_attempts TEXT DEFAULT '[]',
			banned_until BIGINT
		);
	`);
	console.log("✅ Database ready");
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

// ==========================
// VERIFY
// ==========================
app.post("/verify", async (req, res) => {
	const ip =
		req.headers["x-forwarded-for"]?.split(",")[0] ||
		req.socket.remoteAddress;

	const { license, userid, timestamp, nonce } = req.body;

	if (!license || !userid || !timestamp || !nonce) {
		return res.status(400).json({ status: "invalid", reason: "missing_params" });
	}

	// Rate limit
	if (!checkRateLimit(rateLimitIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
		return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
	}

	if (!checkRateLimit(rateLimitLicense, license, RATE_LIMIT_MAX_PER_LICENSE, RATE_LIMIT_WINDOW_MS)) {
		return res.status(429).json({ status: "invalid", reason: "rate_limit_license" });
	}

	// Timestamp
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - Number(timestamp)) > MAX_TIME_DRIFT_SEC) {
		return res.status(401).json({ status: "invalid", reason: "expired" });
	}

	// Anti replay
	const nonceMap = recentNonces.get(license) || new Map();
	if (nonceMap.has(nonce)) {
		return res.status(401).json({ status: "invalid", reason: "replay" });
	}
	nonceMap.set(nonce, Date.now());
	recentNonces.set(license, nonceMap);

	// License lookup
	const result = await pool.query(
		"SELECT * FROM licenses WHERE license = $1",
		[license]
	);

	if (!result.rows.length) {
		return res.status(404).json({ status: "invalid", reason: "unknown_license" });
	}

	const data = result.rows[0];
	const nowMs = Date.now();

	// Ban check
	if (data.banned_until && data.banned_until > nowMs) {
		return res.status(403).json({
			status: "invalid",
			reason: "banned",
			until: data.banned_until
		});
	}

	const allowed = JSON.parse(data.allowed_ids || "[]").map(Number);
	const uid = Number(userid);
	let unauthorized = JSON.parse(data.unauthorized_attempts || "[]");

	if (allowed.includes(uid)) {
		await pool.query(
			"UPDATE licenses SET last_used = $1 WHERE license = $2",
			[Math.floor(nowMs / 1000), license]
		);

		return res.json({ status: "valid" });
	}

	// 🚨 TENTATIVE NON AUTORISÉE - ALERTE DISCORD
	console.log("⚠️ Tentative non autorisée détectée - envoi webhook...");
	sendDiscordAlert(`⚠️ **Tentative non autorisée**\n📝 License: \`${license}\`\n👤 UserID: \`${userid}\`\n🌐 IP: \`${ip}\``);

	if (!unauthorized.includes(uid)) unauthorized.push(uid);

	if (unauthorized.length >= MAX_UNAUTHORIZED_IDS) {
		await pool.query(
			"UPDATE licenses SET unauthorized_attempts=$1, banned_until=$2 WHERE license=$3",
			[JSON.stringify(unauthorized), nowMs + BAN_DURATION_MS, license]
		);

		// 🚨 BAN - ALERTE DISCORD
		console.log("🔴 License bannie - envoi webhook...");
		sendDiscordAlert(`🔴 **LICENSE BANNIE**\n📝 License: \`${license}\`\n⏰ Durée: 48h\n👥 IDs non autorisés: ${unauthorized.length}`);

		return res.status(403).json({
			status: "invalid",
			reason: "banned_unauthorized"
		});
	}

	await pool.query(
		"UPDATE licenses SET unauthorized_attempts=$1 WHERE license=$2",
		[JSON.stringify(unauthorized), license]
	);

	return res.status(403).json({
		status: "invalid",
		reason: "userid_not_allowed"
	});
});

// ==========================
app.get("/health", (_, res) => res.json({ status: "ok" }));

initDatabase().then(() => {
	app.listen(3000, () => console.log("🚀 Server running on port 3000"));
});
