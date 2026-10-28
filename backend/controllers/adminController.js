const db = require("../config/db");

const getDashboard = async (req, res) => {
    try {
        const [[users]] = await db.query(
            "SELECT COUNT(*) AS total FROM users"
        );

        const [[files]] = await db.query(
            "SELECT COUNT(*) AS total FROM files"
        );

        const [[attacks]] = await db.query(
            "SELECT COUNT(*) AS total FROM attack_logs"
        );

        const [[decoys]] = await db.query(
            "SELECT COUNT(*) AS total FROM decoy_files"
        );

        const [[highRisk]] = await db.query(
            "SELECT COUNT(*) AS total FROM risk_scores WHERE risk_level = 'HIGH'"
        );

        const [[downloads]] = await db.query("SELECT COUNT(*) AS total FROM access_logs WHERE action = 'DOWNLOAD' AND access_status = 'ALLOWED'");
        const [[decoyAccesses]] = await db.query("SELECT COUNT(*) AS total FROM access_logs WHERE action = 'DECOY' AND access_status = 'DECOY'");

        res.json({
            success: true,
            dashboard: {
                totalUsers: users.total,
                totalFiles: files.total,
                totalAttacks: attacks.total,
                totalDecoys: decoys.total,
                totalDownloads: downloads.total,
                highRiskEvents: highRisk.total,
                decoyAccesses: decoyAccesses.total
            }
        });

    } catch (error) {
        console.error("Admin dashboard error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load admin dashboard"
        });
    }
};


const getUsers = async (req, res) => {
    try {
        const [users] = await db.query(
            `SELECT
                id,
                name,
                email,
                role,
                is_active,
                created_at
             FROM users
             ORDER BY created_at DESC`
        );

        res.json({
            success: true,
            users
        });

    } catch (error) {
        console.error("Get users error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to get users"
        });
    }
};


const getFiles = async (req, res) => {
    try {
        const [files] = await db.query(
            `SELECT
                f.id,
                f.original_name,
                f.file_size,
                f.mime_type,
                f.encryption_status,
                f.integrity_hash,
                f.created_at,
                u.name AS owner_name,
                u.email AS owner_email
             FROM files f
             JOIN users u ON f.user_id = u.id
             ORDER BY f.created_at DESC`
        );

        res.json({
            success: true,
            files
        });

    } catch (error) {
        console.error("Get files error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to get files"
        });
    }
};


const getAttackLogs = async (req, res) => {
    try {
        const [logs] = await db.query(
            `SELECT
                a.id,
                a.event_type,
                a.risk_score,
                a.risk_level,
                a.ip_address,
                a.device_info,
                a.requested_file,
                a.action_taken,
                a.decoy_accessed,
                a.created_at,
                u.name AS user_name,
                u.email AS user_email
             FROM attack_logs a
             LEFT JOIN users u ON a.user_id = u.id
             ORDER BY a.created_at DESC`
        );

        res.json({
            success: true,
            logs
        });

    } catch (error) {
        console.error("Get attack logs error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to get attack logs"
        });
    }
};


const getRiskScores = async (req, res) => {
    try {
        const [scores] = await db.query(
            `SELECT
                r.id,
                r.user_id,
                r.score,
                r.risk_level,
                r.risk_factors,
                r.decision,
                r.calculated_at,
                u.name AS user_name,
                u.email AS user_email
             FROM risk_scores r
             LEFT JOIN users u ON r.user_id = u.id
             ORDER BY r.calculated_at DESC`
        );

        res.json({
            success: true,
            scores
        });

    } catch (error) {
        console.error("Get risk scores error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to get risk scores"
        });
    }
};


module.exports = {
    getDashboard,
    getUsers,
    getFiles,
    getAttackLogs,
    getRiskScores
};
