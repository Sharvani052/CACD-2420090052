const fs = require("fs");
const path = require("path");
const db = require("../config/db");
const { encryptBuffer, decryptBuffer, calculateHash } = require("../utils/encryption");
const { calculateRisk } = require("../utils/riskEngine");
const { ensureDecoy, decoyPath, safeDownloadName } = require("../utils/decoys");

const realDirectory = path.resolve(__dirname, "../storage/real");
const userAgent = (req) => String(req.headers["user-agent"] || "Unknown").slice(0, 255);

function storedFilePath(storedName) {
    const target = path.resolve(realDirectory, path.basename(String(storedName)));
    return target.startsWith(realDirectory + path.sep) ? target : null;
}

async function logRisk(userId, risk) {
    await db.query("INSERT INTO risk_scores (user_id, score, risk_level, risk_factors, decision) VALUES (?, ?, ?, ?, ?)", [userId, risk.score, risk.level, JSON.stringify(risk.factors), risk.decision]);
}

function setRiskHeaders(res, risk) {
    res.setHeader("X-Risk-Decision", risk.decision);
    res.setHeader("X-Risk-Score", String(risk.score));
    res.setHeader("X-Risk-Level", risk.level);
    res.setHeader("X-Risk-Factors", encodeURIComponent(JSON.stringify(risk.factors)));
}

async function updateContext(userId, req, isDownload) {
    const agent = userAgent(req);
    await db.query(
        `INSERT INTO user_context (user_id, device_info, browser, ip_address, files_accessed, downloads_count, failed_attempts)
         VALUES (?, ?, ?, ?, 1, ?, 0)
         ON DUPLICATE KEY UPDATE device_info = VALUES(device_info), browser = VALUES(browser), ip_address = VALUES(ip_address), access_time = CURRENT_TIMESTAMP,
         files_accessed = files_accessed + 1, downloads_count = downloads_count + VALUES(downloads_count)`,
        [userId, agent, agent.slice(0, 100), req.ip, isDownload ? 1 : 0]
    );
}

const uploadFile = async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });
        const originalName = safeDownloadName(req.file.originalname);
        const original = fs.readFileSync(req.file.path);
        const encrypted = encryptBuffer(original);
        const storedName = `${Date.now()}-${req.file.filename}.enc`;
        const encryptedPath = storedFilePath(storedName);
        fs.mkdirSync(realDirectory, { recursive: true });
        fs.writeFileSync(encryptedPath, Buffer.concat([encrypted.iv, encrypted.authTag, encrypted.encrypted]), { flag: "wx" });
        const [result] = await db.query(
            `INSERT INTO files (user_id, original_name, stored_name, file_size, mime_type, encryption_status, integrity_hash)
             VALUES (?, ?, ?, ?, ?, TRUE, ?)`,
            [req.user.userId, originalName, storedName, req.file.size, req.file.mimetype, calculateHash(original)]
        );
        fs.unlinkSync(req.file.path);
        await db.query("INSERT INTO access_logs (user_id, file_id, action, access_status, risk_score) VALUES (?, ?, 'UPLOAD', 'ALLOWED', 0)", [req.user.userId, result.insertId]);
        return res.status(201).json({ success: true, message: "File uploaded and encrypted successfully", file: { id: result.insertId, originalName, size: req.file.size, mimeType: req.file.mimetype, encrypted: true } });
    } catch (error) {
        console.error("File upload error:", error.message);
        if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(500).json({ success: false, message: "File upload failed" });
    }
};

const listFiles = async (req, res) => {
    try {
        const [files] = await db.query(
            `SELECT id, original_name, file_size, mime_type, encryption_status, created_at
             FROM files WHERE user_id = ? ORDER BY created_at DESC`,
            [req.user.userId]
        );
        return res.json({ success: true, files });
    } catch (error) {
        console.error("List files error:", error.message);
        return res.status(500).json({ success: false, message: "Failed to list files" });
    }
};

async function integrityFailure(userId, req, file, risk) {
    await db.query(
        `INSERT INTO attack_logs (user_id, event_type, risk_score, risk_level, ip_address, device_info, requested_file, action_taken, decoy_accessed)
         VALUES (?, 'FILE_INTEGRITY_FAILURE', ?, ?, ?, ?, ?, 'ACCESS_BLOCKED', FALSE)`,
        [userId, risk.score, risk.level, req.ip, userAgent(req), file.original_name]
    );
}

const accessFile = async (req, res) => {
    try {
        const userId = req.user.userId;
        const fileId = Number(req.params.id);
        if (!Number.isSafeInteger(fileId) || fileId < 1) return res.status(400).json({ success: false, message: "Invalid file ID" });
        const [rows] = await db.query("SELECT id, user_id, original_name, stored_name, mime_type, integrity_hash FROM files WHERE id = ? LIMIT 1", [fileId]);
        if (!rows.length) return res.status(404).json({ success: false, message: "File not found" });
        const file = rows[0];
        if (Number(file.user_id) !== Number(userId)) {
            await db.query("INSERT INTO access_logs (user_id, file_id, action, access_status, risk_score) VALUES (?, ?, 'ACCESS', 'DENIED', 100)", [userId, fileId]);
            return res.status(403).json({ success: false, message: "You are not authorized to access this file" });
        }

        const risk = await calculateRisk(userId, req);
        await logRisk(userId, risk);
        if (risk.decision === "DECOY") {
            const decoy = await ensureDecoy(db, file);
            const filePath = decoyPath(decoy.stored_name);
            if (!filePath || !fs.existsSync(filePath)) throw new Error("Associated decoy file is unavailable");
            await db.query(
                `INSERT INTO attack_logs (user_id, event_type, risk_score, risk_level, ip_address, device_info, requested_file, action_taken, decoy_accessed)
                 VALUES (?, 'HIGH_RISK_FILE_ACCESS', ?, ?, ?, ?, ?, 'DECOY_DELIVERED', TRUE)`,
                [userId, risk.score, risk.level, req.ip, userAgent(req), file.original_name]
            );
            await db.query("INSERT INTO access_logs (user_id, file_id, action, access_status, risk_score) VALUES (?, ?, 'DECOY', 'DECOY', ?)", [userId, fileId, risk.score]);
            await updateContext(userId, req, true);
            setRiskHeaders(res, risk);
            return res.download(filePath, safeDownloadName(decoy.decoy_name));
        }

        const realPath = storedFilePath(file.stored_name);
        if (!realPath || !fs.existsSync(realPath)) return res.status(404).json({ success: false, message: "Encrypted file not found" });
        const payload = fs.readFileSync(realPath);
        if (payload.length < 29) throw new Error("Encrypted file format is invalid");
        let decrypted;
        try {
            decrypted = decryptBuffer(payload.subarray(28), payload.subarray(0, 12), payload.subarray(12, 28));
        } catch (error) {
            await integrityFailure(userId, req, file, risk);
            return res.status(409).json({ success: false, message: "Encrypted file authentication failed" });
        }
        if (calculateHash(decrypted) !== file.integrity_hash) {
            await integrityFailure(userId, req, file, risk);
            return res.status(409).json({ success: false, message: "File integrity verification failed" });
        }
        await updateContext(userId, req, true);
        await db.query("INSERT INTO access_logs (user_id, file_id, action, access_status, risk_score) VALUES (?, ?, 'DOWNLOAD', 'ALLOWED', ?)", [userId, fileId, risk.score]);
        res.setHeader("Content-Type", file.mime_type || "application/octet-stream");
        res.setHeader("Content-Disposition", `attachment; filename="${safeDownloadName(file.original_name)}"`);
        setRiskHeaders(res, risk);
        return res.send(decrypted);
    } catch (error) {
        console.error("File access error:", error.message);
        return res.status(500).json({ success: false, message: "File access failed" });
    }
};

module.exports = { uploadFile, listFiles, accessFile };
