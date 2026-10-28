const db = require("../config/db");
const config = require("../config/riskConfig");


// ======================================================
// CALCULATE USER RISK
// ======================================================

async function calculateRisk(userId, req) {

    const factors = [];
    let score = 0;


    // ==================================================
    // 1. FAILED LOGIN ACTIVITY
    // ==================================================

    const [failedLoginRows] = await db.query(
        `SELECT COUNT(*) AS failed_count
         FROM login_history
         WHERE user_id = ?
         AND success = FALSE
         AND login_time >= DATE_SUB(
             NOW(),
             INTERVAL ? HOUR
         )`,
        [
            userId,
            config.windowHours
        ]
    );

    const loginHistoryFailed =
        Number(
            failedLoginRows[0]?.failed_count || 0
        );


    // ==================================================
    // 2. USER CONTEXT
    // ==================================================

    const [contextRows] = await db.query(
        `SELECT
            files_accessed,
            downloads_count,
            failed_attempts,
            ip_address,
            device_info
         FROM user_context
         WHERE user_id = ?
         ORDER BY id DESC
         LIMIT 1`,
        [userId]
    );


    let contextFailed =
        0;

    if (contextRows.length > 0) {

        contextFailed =
            Number(
                contextRows[0].failed_attempts || 0
            );
    }


    // ==================================================
    // IMPORTANT:
    // Use login_history as the primary source.
    //
    // If login_history contains the attempts, use it.
    // If it does not, use user_context as a fallback.
    // This prevents double counting.
    // ==================================================

    const failedLogins =
        loginHistoryFailed > 0
            ? loginHistoryFailed
            : contextFailed;


    console.log(
        "Failed login activity:",
        failedLogins
    );


    // ==================================================
    // FAILED LOGIN RISK
    // ==================================================

    if (
        failedLogins >=
        config.limits.failedSevere
    ) {

        score +=
            config.weights.failedLogin.severe;

        factors.push(
            `${failedLogins} failed login attempts detected`
        );

    } else if (
        failedLogins >=
        config.limits.failedRepeated
    ) {

        score +=
            config.weights.failedLogin.repeated;

        factors.push(
            `${failedLogins} repeated failed login attempts`
        );

    } else if (
        failedLogins > 0
    ) {

        score +=
            config.weights.failedLogin.one;

        factors.push(
            "Recent failed login attempt"
        );
    }


    // ==================================================
    // 3. FILE ACCESS ACTIVITY
    // ==================================================

    const [[activity]] =
        await db.query(
            `SELECT
                COUNT(*) AS files_accessed,
                COALESCE(
                    SUM(
                        action = 'DOWNLOAD'
                        AND access_status = 'ALLOWED'
                    ),
                    0
                ) AS downloads
             FROM access_logs
             WHERE user_id = ?
             AND action IN (
                 'ACCESS',
                 'DOWNLOAD',
                 'DECOY'
             )
             AND access_time >= DATE_SUB(
                 NOW(),
                 INTERVAL ? HOUR
             )`,
            [
                userId,
                config.windowHours
            ]
        );


    const filesAccessed =
        Number(
            activity?.files_accessed || 0
        );

    const downloads =
        Number(
            activity?.downloads || 0
        );


    console.log(
        "File access activity:",
        filesAccessed
    );

    console.log(
        "Download activity:",
        downloads
    );


    // ==================================================
    // FILE ACCESS RISK
    // ==================================================

    if (
        filesAccessed >=
        config.limits.filesHigh
    ) {

        score +=
            config.weights.fileAccess.high;

        factors.push(
            "Unusually high file access"
        );

    } else if (
        filesAccessed >=
        config.limits.filesElevated
    ) {

        score +=
            config.weights.fileAccess.elevated;

        factors.push(
            "Elevated file access"
        );
    }


    // ==================================================
    // DOWNLOAD RISK
    // ==================================================

    if (
        downloads >=
        config.limits.downloadsHigh
    ) {

        score +=
            config.weights.download.high;

        factors.push(
            "High download activity"
        );

    } else if (
        downloads >=
        config.limits.downloadsElevated
    ) {

        score +=
            config.weights.download.elevated;

        factors.push(
            "Elevated download activity"
        );
    }


    // ==================================================
    // 4. IP / DEVICE CONTEXT
    // ==================================================

    if (contextRows.length > 0) {

        const context =
            contextRows[0];


        // ------------------------------------------------
        // IP CHANGE
        // ------------------------------------------------

        if (
            context.ip_address &&
            context.ip_address !== req.ip
        ) {

            score +=
                config.weights.ipChange;

            factors.push(
                "IP address changed"
            );
        }


        // ------------------------------------------------
        // DEVICE CHANGE
        // ------------------------------------------------

        const currentDevice =
            String(
                req.headers["user-agent"] ||
                "Unknown"
            );


        if (
            context.device_info &&
            context.device_info !== currentDevice
        ) {

            score +=
                config.weights.deviceChange;

            factors.push(
                "Device context changed"
            );
        }
    }


    // ==================================================
    // 5. LIMIT SCORE
    // ==================================================

    score =
        Math.min(
            score,
            100
        );


    // ==================================================
    // 6. DETERMINE RISK LEVEL
    // ==================================================

    let level =
        "LOW";

    let decision =
        "ALLOW_REAL";


    if (
        score >=
        config.thresholds.high
    ) {

        level =
            "HIGH";

        decision =
            "DECOY";

    } else if (
        score >=
        config.thresholds.medium
    ) {

        level =
            "MEDIUM";

        decision =
            "ALLOW_WITH_MONITORING";
    }


    // ==================================================
    // 7. NORMAL USER
    // ==================================================

    if (
        factors.length === 0
    ) {

        factors.push(
            "Normal user behavior"
        );
    }


    // ==================================================
    // 8. DEBUG INFORMATION
    // ==================================================

    console.log(
        "Current risk:",
        {
            score,
            level,
            decision,
            factors
        }
    );


    // ==================================================
    // RETURN
    // ==================================================

    return {
        score,
        level,
        decision,
        factors
    };
}


// ======================================================
// EXPORT
// ======================================================

module.exports = {
    calculateRisk
};