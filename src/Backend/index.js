require("dotenv").config();
require("./scheduler"); // Integrate scheduler directly into backend startup
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { PrismaClient } = require("@prisma/client");
const syncCVEs = require("./services/nvdService");

const prisma = new PrismaClient();
const LOG_FILE = path.join(__dirname, "./data/sync-log.json");

const app = express();

// Enable CORS for frontend requests
app.use(cors());
app.use(express.json());

let isSyncing = false;

// Legacy endpoint compatibility
app.get("/sync-cves", async (req, res) => {
    if (isSyncing) {
        return res.status(409).json({ message: "Sincronización en progreso" });
    }
    
    isSyncing = true;
    try {
        const result = await syncCVEs();
        res.json({
            message: "Sincronización ejecutada",
            details: result
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        isSyncing = false;
    }
});

// GET /sync-status - Returns sync status log file contents directly
app.get("/sync-status", (req, res) => {
    if (fs.existsSync(LOG_FILE)) {
        try {
            const logData = JSON.parse(fs.readFileSync(LOG_FILE, "utf8"));
            return res.json(logData);
        } catch (e) {
            return res.status(500).json({ error: "Error al leer el archivo de log", details: e.message });
        }
    }
    return res.status(404).json({ message: "No se encontró el log de sincronización." });
});

// GET /api/sync/status - Returns last sync log and current status (for UI compatibility)
app.get("/api/sync/status", async (req, res) => {
    let logData = { lastSync: null, status: "PENDING", records: 0 };
    
    if (fs.existsSync(LOG_FILE)) {
        try {
            logData = JSON.parse(fs.readFileSync(LOG_FILE, "utf8"));
        } catch (e) {
            console.error("Error reading sync-log.json", e.message);
        }
    }
    
    try {
        const totalCves = await prisma.cve.count();
        res.json({
            ...logData,
            isSyncing,
            totalCves
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/sync/trigger - Triggers a manual sync in the background
app.post("/api/sync/trigger", async (req, res) => {
    if (isSyncing) {
        return res.status(409).json({ error: "Sincronización ya en curso" });
    }
    
    isSyncing = true;
    console.log("Sincronización manual iniciada en segundo plano.");
    
    syncCVEs()
        .then((result) => {
            console.log("Sincronización de fondo completada:", result.status);
        })
        .catch((err) => {
            console.error("Error en sincronización de fondo:", err.message);
        })
        .finally(() => {
            isSyncing = false;
        });
        
    res.json({ message: "Sincronización de base de amenazas iniciada" });
});

// GET /api/sync/cves - Retrieves paginated, filterable threat catalog
app.get("/api/sync/cves", async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || "";
        const severity = req.query.severity || "";
        
        const where = {};
        
        if (search) {
            where.OR = [
                { cveId: { contains: search } },
                { description: { contains: search } }
            ];
        }
        
        if (severity) {
            if (severity === "Critical") {
                where.cvss = { gte: 9.0, lte: 10.0 };
            } else if (severity === "High") {
                where.cvss = { gte: 7.0, lt: 9.0 };
            } else if (severity === "Medium") {
                where.cvss = { gte: 4.0, lt: 7.0 };
            } else if (severity === "Low") {
                where.cvss = { gte: 0.1, lt: 4.0 };
            }
        }
        
        const total = await prisma.cve.count({ where });
        const cves = await prisma.cve.findMany({
            where,
            orderBy: { modified: "desc" },
            skip: (page - 1) * limit,
            take: limit
        });
        
        res.json({
            cves,
            pagination: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/cves/:cveId - Retrieves details for a specific CVE ID
app.get("/api/cves/:cveId", async (req, res) => {
    const { cveId } = req.params;
    try {
        let cve = await prisma.cve.findUnique({
            where: { cveId }
        });
        
        if (!cve) {
            // Fallback: search in cves.json
            const CVE_FILE = path.join(__dirname, "./data/cves.json");
            if (fs.existsSync(CVE_FILE)) {
                const fileContent = fs.readFileSync(CVE_FILE, "utf8");
                if (fileContent.trim()) {
                    const cves = JSON.parse(fileContent);
                    const found = cves.find(c => c.cveId.toLowerCase() === cveId.toLowerCase());
                    if (found) {
                        cve = found;
                    }
                }
            }
        }
        
        if (!cve) {
            return res.status(404).json({ error: `CVE ${cveId} no encontrado en el catálogo.` });
        }
        
        return res.json(cve);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// POST /api/cves/correlate - Enrich finding list with CVE catalog metadata (CVSS, description)
app.post("/api/cves/correlate", async (req, res) => {
    const { findings } = req.body;
    if (!Array.isArray(findings)) {
        return res.status(400).json({ error: "El cuerpo de la petición debe contener un arreglo de 'findings'." });
    }
    
    try {
        const correlated = [];
        
        // Unique CVE IDs
        const cveIds = [...new Set(findings.map(f => f.cveId).filter(Boolean))];
        
        // Fetch from Database
        const cveRecords = await prisma.cve.findMany({
            where: {
                cveId: { in: cveIds }
            }
        });
        
        const cveMap = new Map(cveRecords.map(c => [c.cveId.toLowerCase(), c]));
        
        // Fetch from fallback JSON file if any requested CVE was missing in Database
        let jsonCves = [];
        const missingCveIds = cveIds.filter(id => !cveMap.has(id.toLowerCase()));
        if (missingCveIds.length > 0) {
            const CVE_FILE = path.join(__dirname, "./data/cves.json");
            if (fs.existsSync(CVE_FILE)) {
                try {
                    const fileContent = fs.readFileSync(CVE_FILE, "utf8");
                    if (fileContent.trim()) {
                        jsonCves = JSON.parse(fileContent);
                    }
                } catch (e) {
                    console.error("Error al leer el archivo fallback de cves.json en correlación:", e.message);
                }
            }
        }
        
        for (const finding of findings) {
            const cveIdLower = finding.cveId ? finding.cveId.toLowerCase() : "";
            let cveData = cveMap.get(cveIdLower);
            
            if (!cveData && cveIdLower) {
                const foundInJson = jsonCves.find(c => c.cveId.toLowerCase() === cveIdLower);
                if (foundInJson) {
                    cveData = foundInJson;
                }
            }
            
            if (cveData) {
                correlated.push({
                    ...finding,
                    cvss: cveData.cvss,
                    description: cveData.description,
                    published: cveData.published,
                    modified: cveData.modified,
                    correlated: true
                });
            } else {
                correlated.push({
                    ...finding,
                    correlated: false
                });
            }
        }
        
        return res.json({ findings: correlated });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor Express corriendo en puerto ${PORT}`);
});