const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

function applySecurity(app) {
    app.use(helmet({ crossOriginResourcePolicy: false }));
    app.use(cors({ origin: process.env.FRONTEND_URL || "http://localhost:5173", credentials: true }));
    app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 50, standardHeaders: true, legacyHeaders: false }));
}

module.exports = { applySecurity };
