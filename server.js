import express from "express";
import crypto from "crypto";
import fs from "fs";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(express.json());

// ==========================
// CONFIG SÉCURITÉ
// ==========================
const SECRET_KEY = "rREd764dJYU7665dsfEF"; // change-la et garde-la privée
const MAX_TIME_DRIFT_SEC = 300; // 5 minutes
const MAX_UNAUTHORIZED_IDS = 3; // Tentatives UserId non autorisés avant ban
const BAN_DURATION_MS = 48 * 60 * 60 * 1000; // 48h
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_PER_LICENSE = 30; // max 30 req / minute / license
const RATE_LIMIT_MAX_PER_IP = 60; // max 60 req / minute / IP

// Connexion Render PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ==========================
// CRÉATION DES TABLES
// ==========================
async function initDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS licenses (
            license TEXT PRIMARY KEY,
            owner_id BIGINT,
            allowed_ids TEXT,
            last_used BIGINT,
            unauthorized_attempts TEXT DEFAULT '[]',
            banned_until BIGINT,
            created_at BIGINT
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS access_logs (
            id SERIAL PRIMARY KEY,
            license TEXT,
            user_id BIGINT,
            success BOOLEAN,
            reason TEXT,
            ip TEXT,
            timestamp BIGINT
        );
    `);

    console.log("Tables 'licenses' et 'access_logs' OK");
}

// ==========================
// CHARGER licenses.txt
// Format :
// License: AcETVk37f6sg0
// UserID: 1745237976
// UserID: 7522968393
//
// License: AUTREKEY
// UserID: 111
// UserID: 222
// ==========================
async function loadLicensesFromFile() {
    if (!fs.existsSync("licenses.txt")) {
        console.warn("licenses.txt non trouvé, aucun chargement.");
        return;
    }

    const content = fs.readFileSync("licenses.txt", "utf8");
    const lines = content.split("\n");

    let currentLicense = null;
    let users = [];

    for (let rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;

        if (line.toLowerCase().startsWith("license:")) {
            // Sauvegarder la précédente licence
            if (currentLicense !== null) {
                await saveLicenseFromFile(currentLicense, users);
            }
            currentLicense = line.split(":")[1].trim();
            users = [];
        } else if (line.toLowerCase().startsWith("userid:")) {
            const uid = line.split(":")[1].trim();
            if (uid) users.push(uid);
        }
    }

    // Dernière licence
    if (currentLicense !== null) {
        await saveLicenseFromFile(currentLicense, users);
    }

    console.log("Licenses chargées depuis licenses.txt");
}

async function saveLicenseFromFile(license, users) {
    const now = Date.now();
    await pool.query(`
        INSERT INTO licenses (license, owner_id, allowed_ids, last_used, unauthorized_attempts, banned_until, created_at)
        VALUES ($1, $2, $3, NULL, '[]', NULL, $4)
        ON CONFLICT (license) DO UPDATE SET
            allowed_ids = $3
    `, [license, 0, JSON.stringify(users.map(u => parseInt(u))), now]);
}

// ==========================
// ANTI-REPLAY & RATE-LIMIT
// ==========================
const recentNonces = new Map(); // key = license, value = Map(nonce -> timestamp)
const rateLimitPerLicense = new Map(); // key = license, value = {count, windowStart}
const rateLimitPerIP = new Map(); // key = ip, value = {count, windowStart}

function cleanOldNonces() {
    const now = Date.now();
    const maxAge = MAX_TIME_DRIFT_SEC * 1000;

    for (const [license, nonceMap] of recentNonces.entries()) {
        for (const [nonce, ts] of nonceMap.entries()) {
            if (now - ts > maxAge) {
                nonceMap.delete(nonce);
            }
        }
        if (nonceMap.size === 0) {
            recentNonces.delete(license);
        }
    }
}

setInterval(cleanOldNonces, 60 * 1000); // nettoyage chaque minute

function checkRateLimit(map, key, limit, windowMs) {
    const now = Date.now();
    const entry = map.get(key);

    if (!entry) {
        map.set(key, { count: 1, windowStart: now });
        return true;
    }

    if (now - entry.windowStart > windowMs) {
        map.set(key, { count: 1, windowStart: now });
        return true;
    }

    if (entry.count >= limit) {
        return false;
    }

    entry.count++;
    return true;
}

// ==========================
// HMAC + TIMING SAFE
// ==========================
function verifyHMAC(license, userid, timestamp, nonce, signature) {
    const message = `${license}${userid}${timestamp}${nonce}`;
    const expected = crypto
        .createHmac("sha256", SECRET_KEY)
        .update(message)
        .digest("hex");

    try {
        return crypto.timingSafeEqual(
            Buffer.from(signature, "hex"),
            Buffer.from(expected, "hex")
        );
    } catch {
        return false;
    }
}

// ==========================
// LOGGING
// ==========================
async function logAccess(license, userId, success, reason, ip) {
    try {
        await pool.query(
            `INSERT INTO access_logs (license, user_id, success, reason, ip, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [license || null, userId || null, success, reason || null, ip || null, Math.floor(Date.now() / 1000)]
        );
    } catch (e) {
        console.error("Erreur logAccess:", e.message);
    }
}

// ==========================
// ENDPOINT PRINCIPAL /verify
// ==========================
app.post("/verify", async (req, res) => {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
    const { license, userid, timestamp, nonce, signature } = req.body;

    // Paramètres requis
    if (!license || !userid || !timestamp || !nonce || !signature) {
        await logAccess(license, userid, false, "Missing parameters", ip);
        return res.status(400).json({ status: "invalid", reason: "missing_parameters" });
    }

    // Rate limit IP
    if (!checkRateLimit(rateLimitPerIP, ip, RATE_LIMIT_MAX_PER_IP, RATE_LIMIT_WINDOW_MS)) {
        await logAccess(license, userid, false, "Rate limit IP", ip);
        return res.status(429).json({ status: "invalid", reason: "rate_limit_ip" });
    }

    // Rate limit par license
    if (!checkRateLimit(rateLimitPerLicense, license, RATE_LIMIT_MAX_PER_LICENSE, RATE_LIMIT_WINDOW_MS)) {
        await logAccess(license, userid, false, "Rate limit license", ip);
        return res.status(429).json({ status: "invalid", reason: "rate_limit_license" });
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const reqTime = parseInt(timestamp, 10);

    if (Number.isNaN(reqTime) || Math.abs(nowSec - reqTime) > MAX_TIME_DRIFT_SEC) {
        await logAccess(license, userid, false, "Timestamp expired", ip);
        return res.status(401).json({ status: "invalid", reason: "request_expired" });
    }

    // Anti-replay (nonce déjà utilisé pour cette licence)
    const nonceMap = recentNonces.get(license) || new Map();
    if (nonceMap.has(nonce)) {
        await logAccess(license, userid, false, "Replay attack", ip);
        return res.status(401).json({ status: "invalid", reason: "replay_detected" });
    }
    nonceMap.set(nonce, Date.now());
    recentNonces.set(license, nonceMap);

    // Vérification HMAC
    const hmacOk = verifyHMAC(license, userid, timestamp, nonce, signature);
    if (!hmacOk) {
        await logAccess(license, userid, false, "Invalid signature", ip);
        return res.status(401).json({ status: "invalid", reason: "bad_signature" });
    }

    // Récup licence
    const result = await pool.query(`SELECT * FROM licenses WHERE license = $1`, [license]);
    if (result.rows.length === 0) {
        await logAccess(license, userid, false, "License not found", ip);
        return res.status(404).json({ status: "invalid", reason: "unknown_license" });
    }

    const data = result.rows[0];
    const nowMs = Date.now();
    const nowSecInt = Math.floor(nowMs / 1000);

    // Ban actif ?
    if (data.banned_until && Number(data.banned_until) > nowMs) {
        const hoursLeft = Math.ceil((Number(data.banned_until) - nowMs) / (1000 * 60 * 60));
        await logAccess(license, userid, false, `Banned (${hoursLeft}h left)`, ip);
        return res.status(403).json({
            status: "invalid",
            reason: "license_suspended",
            banned_until: Number(data.banned_until),
            hours_left: hoursLeft
        });
    }

    // Auto unban si temps dépassé
    if (data.banned_until && Number(data.banned_until) <= nowMs) {
        await pool.query(
            `UPDATE licenses SET banned_until = NULL, unauthorized_attempts = '[]' WHERE license = $1`,
            [license]
        );
    }

    // IDs autorisés
    const allowedIds = JSON.parse(data.allowed_ids || "[]").map(v => Number(v));
    const uidNum = Number(userid);
    let unauthorizedAttempts = JSON.parse(data.unauthorized_attempts || "[]").map(v => Number(v));

    if (allowedIds.includes(uidNum)) {
        // ✅ Autorisé
        await pool.query(
            `UPDATE licenses SET last_used = $1 WHERE license = $2`,
            [nowSecInt, license]
        );
        await logAccess(license, userid, true, "Authorized", ip);

        return res.json({
            status: "valid",
            owner_id: data.owner_id,
            message: "license_valid"
        });
    } else {
        // ❌ Non autorisé
        if (!unauthorizedAttempts.includes(uidNum)) {
            unauthorizedAttempts.push(uidNum);
        }

        // Ban si trop d’UID non autorisés
        if (unauthorizedAttempts.length >= MAX_UNAUTHORIZED_IDS) {
            const banUntil = nowMs + BAN_DURATION_MS;
            await pool.query(
                `UPDATE licenses SET unauthorized_attempts = $1, banned_until = $2 WHERE license = $3`,
                [JSON.stringify(unauthorizedAttempts), banUntil, license]
            );
            await logAccess(license, userid, false, "BANNED - too many unauthorized attempts", ip);

            return res.status(403).json({
                status: "invalid",
                reason: "license_suspended_unauthorized_attempts",
                banned_until: banUntil,
                attempts: unauthorizedAttempts.length,
                max_attempts: MAX_UNAUTHORIZED_IDS
            });
        } else {
            await pool.query(
                `UPDATE licenses SET unauthorized_attempts = $1 WHERE license = $2`,
                [JSON.stringify(unauthorizedAttempts), license]
            );
        }

        await logAccess(
            license,
            userid,
            false,
            `Unauthorized UserID (${unauthorizedAttempts.length}/${MAX_UNAUTHORIZED_IDS})`,
            ip
        );

        return res.status(403).json({
            status: "invalid",
            reason: "userid_not_allowed",
            attempts: unauthorizedAttempts.length,
            max_attempts: MAX_UNAUTHORIZED_IDS
        });
    }
});

// Healthcheck simple
app.get("/health", (req, res) => {
    res.json({ status: "online", timestamp: Date.now() });
});


// TEMPORAIRE : corriger la base
app.get("/fixdb", async (req, res) => {
    try {
        await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS unauthorized_attempts TEXT DEFAULT '[]';`);
        await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS banned_until BIGINT;`);
        await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_at BIGINT;`);
        await pool.query(`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS allowed_ids TEXT;`);

        res.send("Database fixed!");
    } catch (err) {
        res.send("Error: " + err.message);
    }
});


// ==========================
// DÉMARRAGE
// ==========================
async function start() {
    await initDatabase();
    await loadLicensesFromFile();
    app.listen(3000, () => console.log("Server running on port 3000"));
}

start().catch(err => {
    console.error("Erreur au démarrage:", err);
    process.exit(1);
});
