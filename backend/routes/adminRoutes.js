const express = require("express");

const {
    getDashboard,
    getUsers,
    getFiles,
    getAttackLogs,
    getRiskScores
} = require("../controllers/adminController");

const authMiddleware = require("../middleware/authMiddleware");
const requireAdmin = require("../middleware/adminMiddleware");

const router = express.Router();


router.use(authMiddleware, requireAdmin);

router.get("/dashboard", getDashboard);


router.get(
    "/users",
    getUsers
);


router.get(
    "/files",
    getFiles
);


router.get(
    "/attacks",
    getAttackLogs
);


router.get(
    "/risk-scores",
    getRiskScores
);


module.exports = router;
