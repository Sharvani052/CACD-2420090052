const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const {
    uploadFile,
    listFiles,
    accessFile
} = require("../controllers/fileController");

const authMiddleware =
    require("../middleware/authMiddleware");

const router = express.Router();


// ======================================================
// TEMP UPLOAD DIRECTORY
// ======================================================

const uploadDirectory =
    path.join(__dirname, "../storage/temp");


// Create directory if it doesn't exist

if (!fs.existsSync(uploadDirectory)) {
    fs.mkdirSync(uploadDirectory, {
        recursive: true
    });
}


// ======================================================
// MULTER STORAGE
// ======================================================

const storage =
    multer.diskStorage({

        destination: (req, file, cb) => {

            cb(
                null,
                uploadDirectory
            );
        },

        filename: (req, file, cb) => {

            const uniqueName =
                `${Date.now()}-${Math.round(
                    Math.random() * 1E9
                )}-${file.originalname}`;

            cb(
                null,
                uniqueName
            );
        }
    });


// ======================================================
// MULTER CONFIGURATION
// ======================================================

const upload =
    multer({

        storage,

        limits: {
            fileSize:
                10 * 1024 * 1024
        },
        fileFilter: (req, file, cb) => {
            if (!file.originalname || path.basename(file.originalname) !== file.originalname) {
                return cb(new Error("Invalid upload filename"));
            }
            cb(null, true);
        }
    });


// ======================================================
// UPLOAD
// ======================================================

router.post(
    "/upload",
    authMiddleware,
    upload.single("file"),
    uploadFile
);

router.get("/", authMiddleware, listFiles);


// ======================================================
// SECURE FILE ACCESS
// ======================================================

router.get(
    "/:id",
    authMiddleware,
    accessFile
);


// ======================================================
// EXPORT
// ======================================================

module.exports = router;
