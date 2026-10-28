const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");
const { Document, Packer, Paragraph, TextRun } = require("docx");

const decoyDirectory = path.resolve(__dirname, "../storage/decoys");

function safeDownloadName(name) {
    return path.basename(String(name || "download")).replace(/[\r\n"]/g, "_").slice(0, 200) || "download";
}

function decoyLines(originalName) {
    return ["DEMONSTRATION DECOY FILE", "This harmless file was delivered because the access session triggered the adaptive-risk policy.", "It contains no sensitive or production information.", `Reference: ${safeDownloadName(originalName)}`];
}

function createDecoyContent(originalName) {
    if (path.extname(originalName).toLowerCase() === ".csv") return "employee_id,department,classification,status\nD-1001,Research,Sample,Active\nD-1002,Operations,Sample,Active\n";
    return `${decoyLines(originalName).join("\n")}\n`;
}

function createPdfDecoy(originalName) {
    return new Promise((resolve, reject) => {
        const document = new PDFDocument({ margin: 56 });
        const chunks = [];
        document.on("data", (chunk) => chunks.push(chunk));
        document.on("end", () => resolve(Buffer.concat(chunks)));
        document.on("error", reject);
        document.fontSize(20).fillColor("#4c1d95").text("Demonstration Decoy File");
        document.moveDown().fontSize(11).fillColor("#111827");
        decoyLines(originalName).slice(1).forEach((line) => document.text(line, { paragraphGap: 10 }));
        document.end();
    });
}

async function createDocxDecoy(originalName) {
    const document = new Document({ sections: [{ children: [
        new Paragraph({ children: [new TextRun({ text: "Demonstration Decoy File", bold: true, size: 32, color: "4C1D95" })] }),
        ...decoyLines(originalName).slice(1).map((line) => new Paragraph(line))
    ] }] });
    return Packer.toBuffer(document);
}

async function createDecoyBuffer(originalName) {
    const extension = path.extname(originalName).toLowerCase();
    if (extension === ".pdf") return createPdfDecoy(originalName);
    if (extension === ".docx") return createDocxDecoy(originalName);
    return Buffer.from(createDecoyContent(originalName), "utf8");
}

async function ensureDecoy(db, file) {
    const [existing] = await db.query("SELECT id, decoy_name, stored_name FROM decoy_files WHERE file_id = ? ORDER BY id DESC LIMIT 1", [file.id]);
    if (existing.length) return existing[0];
    fs.mkdirSync(decoyDirectory, { recursive: true });
    const decoyName = safeDownloadName(file.original_name);
    const extension = path.extname(decoyName).toLowerCase();
    const storedName = `decoy-${file.id}-${Date.now()}${extension || ".txt"}`;
    fs.writeFileSync(path.join(decoyDirectory, storedName), await createDecoyBuffer(decoyName), { flag: "wx" });
    const [result] = await db.query("INSERT INTO decoy_files (file_id, decoy_name, stored_name, description) VALUES (?, ?, ?, ?)", [file.id, decoyName, storedName, "Automatically generated harmless context-aware decoy"]);
    return { id: result.insertId, decoy_name: decoyName, stored_name: storedName };
}

function decoyPath(storedName) {
    const target = path.resolve(decoyDirectory, path.basename(String(storedName)));
    return target.startsWith(decoyDirectory + path.sep) ? target : null;
}

module.exports = { ensureDecoy, decoyPath, safeDownloadName, createDecoyBuffer };
