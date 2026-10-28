const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");


// ======================================================
// REGISTER
// ======================================================

const register = async (req, res) => {

    try {

        const name =
            String(
                req.body.name || ""
            ).trim();

        const email =
            String(
                req.body.email || ""
            ).trim().toLowerCase();

        const password =
            String(
                req.body.password || ""
            );


        // ------------------------------------------------
        // VALIDATION
        // ------------------------------------------------

        if (
            !name ||
            !/^\S+@\S+\.\S+$/.test(email) ||
            password.length < 8
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Provide a name, valid email, and password of at least 8 characters"
            });
        }


        // ------------------------------------------------
        // CHECK EXISTING USER
        // ------------------------------------------------

        const [existingUsers] =
            await db.query(
                "SELECT id FROM users WHERE email = ?",
                [email]
            );


        if (
            existingUsers.length > 0
        ) {

            return res.status(409).json({
                success: false,
                message:
                    "Email already registered"
            });
        }


        // ------------------------------------------------
        // HASH PASSWORD
        // ------------------------------------------------

        const hashedPassword =
            await bcrypt.hash(
                password,
                10
            );


        // ------------------------------------------------
        // CREATE USER
        // ------------------------------------------------

        const [result] =
            await db.query(
                `INSERT INTO users
                (
                    name,
                    email,
                    password
                )
                VALUES (?, ?, ?)`,
                [
                    name,
                    email,
                    hashedPassword
                ]
            );


        return res.status(201).json({
            success: true,
            message:
                "User registered successfully",
            userId:
                result.insertId
        });

    } catch (error) {

        console.error(
            "Register error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Registration failed"
        });
    }
};


// ======================================================
// LOGIN
// ======================================================

const login = async (req, res) => {

    try {

        const email =
            String(
                req.body.email || ""
            ).trim().toLowerCase();

        const password =
            String(
                req.body.password || ""
            );


        // ------------------------------------------------
        // VALIDATION
        // ------------------------------------------------

        if (
            !email ||
            !password
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Email and password are required"
            });
        }


        // ------------------------------------------------
        // FIND USER
        // ------------------------------------------------

        const [users] =
            await db.query(
                `SELECT
                    id,
                    name,
                    email,
                    password,
                    role,
                    is_active
                 FROM users
                 WHERE email = ?`,
                [email]
            );


        // ------------------------------------------------
        // UNKNOWN USER
        // ------------------------------------------------

        if (
            users.length === 0
        ) {

            await db.query(
                `INSERT INTO login_history
                (
                    user_id,
                    ip_address,
                    user_agent,
                    success
                )
                VALUES (NULL, ?, ?, FALSE)`,
                [
                    req.ip,
                    req.headers["user-agent"] ||
                        "Unknown"
                ]
            );


            return res.status(401).json({
                success: false,
                message:
                    "Invalid email or password"
            });
        }


        const user =
            users[0];


        // ------------------------------------------------
        // INACTIVE ACCOUNT
        // ------------------------------------------------

        if (
            !user.is_active
        ) {

            return res.status(403).json({
                success: false,
                message:
                    "Account is inactive"
            });
        }


        // ------------------------------------------------
        // CHECK PASSWORD
        // ------------------------------------------------

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );


        // =================================================
        // FAILED LOGIN
        // =================================================

        if (
            !passwordMatch
        ) {

            // ---------------------------------------------
            // Record failed login
            // ---------------------------------------------

            await db.query(
                `INSERT INTO login_history
                (
                    user_id,
                    ip_address,
                    user_agent,
                    success
                )
                VALUES (?, ?, ?, FALSE)`,
                [
                    user.id,
                    req.ip,
                    req.headers["user-agent"] ||
                        "Unknown"
                ]
            );


            // ---------------------------------------------
            // Update user context
            // ---------------------------------------------

            await db.query(
                `INSERT INTO user_context
                (
                    user_id,
                    device_info,
                    browser,
                    ip_address,
                    files_accessed,
                    downloads_count,
                    failed_attempts
                )
                VALUES (?, ?, ?, ?, 0, 0, 1)

                ON DUPLICATE KEY UPDATE

                    device_info =
                        VALUES(device_info),

                    browser =
                        VALUES(browser),

                    ip_address =
                        VALUES(ip_address),

                    failed_attempts =
                        failed_attempts + 1`,
                [
                    user.id,

                    String(
                        req.headers["user-agent"] ||
                        "Unknown"
                    ).slice(
                        0,
                        255
                    ),

                    String(
                        req.headers["user-agent"] ||
                        "Unknown"
                    ).slice(
                        0,
                        100
                    ),

                    req.ip
                ]
            );


            console.log(
                `Failed login recorded for user ${user.id}`
            );


            return res.status(401).json({
                success: false,
                message:
                    "Invalid email or password"
            });
        }


        // =================================================
        // SUCCESSFUL LOGIN
        // =================================================

        const token =
            jwt.sign(
                {
                    userId:
                        user.id,

                    role:
                        user.role
                },

                process.env.JWT_SECRET,

                {
                    expiresIn:
                        "1h"
                }
            );


        // ------------------------------------------------
        // Record successful login
        // ------------------------------------------------

        await db.query(
            `INSERT INTO login_history
            (
                user_id,
                ip_address,
                user_agent,
                success
            )
            VALUES (?, ?, ?, TRUE)`,
            [
                user.id,
                req.ip,
                req.headers["user-agent"] ||
                    "Unknown"
            ]
        );


        // ------------------------------------------------
        // Log successful login
        // ------------------------------------------------

        await db.query(
            `INSERT INTO access_logs
            (
                user_id,
                file_id,
                action,
                access_status,
                risk_score
            )
            VALUES (?, NULL, ?, ?, ?)`,
            [
                user.id,
                "LOGIN_SUCCESS",
                "ALLOWED",
                0
            ]
        );


        // ------------------------------------------------
        // Successful response
        // ------------------------------------------------

        return res.json({
            success: true,
            message:
                "Login successful",

            token,

            user: {
                id:
                    user.id,

                name:
                    user.name,

                email:
                    user.email,

                role:
                    user.role
            }
        });

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Login failed"
        });
    }
};


// ======================================================
// GET CURRENT USER
// ======================================================

const getMe = async (req, res) => {

    try {

        const [users] =
            await db.query(
                `SELECT
                    id,
                    name,
                    email,
                    role,
                    is_active,
                    created_at
                 FROM users
                 WHERE id = ?`,
                [
                    req.user.userId
                ]
            );


        if (
            users.length === 0
        ) {

            return res.status(404).json({
                success: false,
                message:
                    "User not found"
            });
        }


        return res.json({
            success: true,
            user:
                users[0]
        });

    } catch (error) {

        console.error(
            "Get user error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Failed to get user"
        });
    }
};


// ======================================================
// EXPORTS
// ======================================================

module.exports = {
    register,
    login,
    getMe
};