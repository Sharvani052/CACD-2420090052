const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

dotenv.config();

const db = require("./config/db");

const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const fileRoutes = require("./routes/fileRoutes");

const app = express();

const PORT = process.env.PORT || 5000;

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin: process.env.FRONTEND_URL || "http://localhost:5173",
        credentials: true,
        exposedHeaders: ["X-Risk-Decision", "X-Risk-Score", "X-Risk-Level", "X-Risk-Factors"]
    })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);

const storagePath = path.join(__dirname, "storage");

const tempPath = path.join(storagePath, "temp");
const realPath = path.join(storagePath, "real");
const decoyPath = path.join(storagePath, "decoys");

if (!fs.existsSync(tempPath)) {
    fs.mkdirSync(tempPath, { recursive: true });
}

if (!fs.existsSync(realPath)) {
    fs.mkdirSync(realPath, { recursive: true });
}

if (!fs.existsSync(decoyPath)) {
    fs.mkdirSync(decoyPath, { recursive: true });
}

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "Adaptive Decoy Security API is running"
    });
});

app.get("/api/health", async (req, res) => {
    try {
        const [result] = await db.query("SELECT 1 AS test");

        res.json({
            success: true,
            backend: "healthy",
            database: "connected",
            test: result[0].test
        });

    } catch (error) {
        console.error("Health check error:", error);

        res.status(500).json({
            success: false,
            backend: "healthy",
            database: "disconnected"
        });
    }
});

app.use("/api/auth", rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: "Too many authentication requests; try again later" }
}));

app.use("/api/auth", authRoutes);

app.use("/api/admin", adminRoutes);

app.use("/api/files", fileRoutes);

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "API endpoint not found"
    });
});

app.use((error, req, res, next) => {
    if (error instanceof require("multer").MulterError) {
        return res.status(400).json({ success: false, message: error.code === "LIMIT_FILE_SIZE" ? "File exceeds the 10 MB limit" : "Invalid file upload" });
    }
    if (error.message === "Invalid upload filename") return res.status(400).json({ success: false, message: error.message });
    console.error("Unhandled server error:", error);

    res.status(500).json({
        success: false,
        message: "Internal server error"
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
