const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";

function getEncryptionKey() {
    const secret = process.env.ENCRYPTION_KEY;

    if (!secret) {
        throw new Error("ENCRYPTION_KEY is not configured");
    }

    return crypto
        .createHash("sha256")
        .update(secret, "utf8")
        .digest();
}

function encryptBuffer(buffer) {
    const key = getEncryptionKey();

    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        ALGORITHM,
        key,
        iv
    );

    const encrypted = Buffer.concat([
        cipher.update(buffer),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return {
        encrypted,
        iv,
        authTag
    };
}

function decryptBuffer(encrypted, iv, authTag) {
    const key = getEncryptionKey();

    if (!Buffer.isBuffer(encrypted)) {
        encrypted = Buffer.from(encrypted);
    }

    if (!Buffer.isBuffer(iv)) {
        iv = Buffer.from(iv);
    }

    if (!Buffer.isBuffer(authTag)) {
        authTag = Buffer.from(authTag);
    }

    if (iv.length !== 12) {
        throw new Error("Invalid IV length");
    }

    if (authTag.length !== 16) {
        throw new Error("Invalid authentication tag length");
    }

    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        key,
        iv
    );

    decipher.setAuthTag(authTag);

    return Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);
}

function calculateHash(buffer) {
    return crypto
        .createHash("sha256")
        .update(buffer)
        .digest("hex");
}

module.exports = {
    encryptBuffer,
    decryptBuffer,
    calculateHash
};