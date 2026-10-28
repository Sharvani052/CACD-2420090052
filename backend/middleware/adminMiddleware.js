const requireAdmin = (req, res, next) => {
    if (req.user?.role !== "ADMIN") {
        return res.status(403).json({ success: false, message: "Administrator access is required" });
    }
    next();
};

module.exports = requireAdmin;
