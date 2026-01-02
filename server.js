import express from "express";
import crypto from "crypto";
import fs from "fs";
import pkg from "pg";

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

// PostgreSQL (Render)
const pool = new Pool({
	connectionString: process.env.DATABASE_URL,
	ssl: { rejectUnauthorized: false }
});

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

	console.log("Database ready");
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

	if (!unauthorized.includes(uid)) unauthorized.push(uid);

	if (unauthorized.length >= MAX_UNAUTHORIZED_IDS) {
		await pool.query(
			"UPDATE licenses SET unauthorized_attempts=$1, banned_until=$2 WHERE license=$3",
			[JSON.stringify(unauthorized), nowMs + BAN_DURATION_MS, license]
		);

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

app.listen(3000, () => console.log("Server running on 3000"));
