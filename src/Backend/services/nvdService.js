require("dotenv").config();
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

const CVE_FILE = path.join(__dirname, "../data/cves.json");
const LOG_FILE = path.join(__dirname, "../data/sync-log.json");

// Ensure data directory exists
const dataDir = path.dirname(CVE_FILE);
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Helper to perform HTTP requests with exponential backoff on rate limits / network errors
async function fetchWithRetry(url, headers, retries = 5, initialDelay = 2000) {
    let delay = initialDelay;
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const response = await axios.get(url, {
                timeout: 30000,
                headers: headers
            });
            return response;
        } catch (error) {
            const status = error.response ? error.response.status : null;
            const isRateLimit = status === 403 || status === 429;
            const isNetworkError = !error.response;

            if ((isRateLimit || isNetworkError) && attempt < retries) {
                console.warn(`[Intento ${attempt}/${retries}] Alerta de Rate Limit o Error de red (Status: ${status || "Red"}). Reintentando en ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));
                delay *= 2; // exponential backoff
            } else {
                throw error;
            }
        }
    }
}

// Helper to merge new CVEs into the JSON catalog file based on cveId (Upsert)
function mergeCVEsIntoJsonFile(newCves) {
    let existingCves = [];
    if (fs.existsSync(CVE_FILE)) {
        try {
            const fileContent = fs.readFileSync(CVE_FILE, "utf8");
            if (fileContent.trim()) {
                existingCves = JSON.parse(fileContent);
            }
        } catch (err) {
            console.error("Error al leer el archivo cves.json existente, iniciando nuevo:", err.message);
        }
    }

    // Map existing by cveId
    const cveMap = new Map(existingCves.map(cve => [cve.cveId, cve]));
    // Upsert new ones
    for (const cve of newCves) {
        cveMap.set(cve.cveId, cve);
    }

    // Save back
    const updatedCves = Array.from(cveMap.values());
    fs.writeFileSync(CVE_FILE, JSON.stringify(updatedCves, null, 2));
    return updatedCves.length;
}

async function syncCVEs() {
    let lastSync = null;
    const endDate = new Date().toISOString();
    
    // Read API key from environment
    const apiKey = process.env.NVD_API_KEY;
    const headers = {
        "User-Agent": "Atrox-CVE-Sync/1.0"
    };
    if (apiKey) {
        headers["apiKey"] = apiKey;
        console.log("Sincronización NVD: Usando API Key de las variables de entorno.");
    } else {
        console.log("Sincronización NVD: Ejecutando SIN API Key. El rate limit estará restringido.");
    }

    // Determine polite delay between requests: 600ms with API key, 6000ms without API key.
    const requestDelay = apiKey ? 600 : 6000;

    try {
        if (fs.existsSync(LOG_FILE)) {
            const content = fs.readFileSync(LOG_FILE, "utf8");
            if (content.trim()) {
                const log = JSON.parse(content);
                lastSync = log.lastSync || null;
            }
        }

        const params = new URLSearchParams();

        if (lastSync) {
            const startMs = Date.parse(lastSync);
            const endMs = Date.parse(endDate);
            const maxRangeMs = 120 * 24 * 60 * 60 * 1000; // 120 days limit by NVD
            let adjustedStart = lastSync;
            
            if (endMs - startMs > maxRangeMs) {
                console.log("Ajustando rango de sincronización a los últimos 120 días.");
                adjustedStart = new Date(endMs - maxRangeMs).toISOString();
            }

            // Format to YYYY-MM-DDTHH:mm:ssZ
            const formattedStart = new Date(adjustedStart).toISOString().split('.')[0] + 'Z';
            const formattedEnd = new Date(endDate).toISOString().split('.')[0] + 'Z';

            params.append("lastModStartDate", formattedStart);
            params.append("lastModEndDate", formattedEnd);
        }

        let totalResults = 0;
        let startIndex = 0;
        const resultsPerPage = 2000; // Max allowed by NVD API
        let totalProcessed = 0;

        do {
            const pageParams = new URLSearchParams(params);
            pageParams.append("resultsPerPage", resultsPerPage.toString());
            pageParams.append("startIndex", startIndex.toString());

            const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${pageParams.toString()}`;
            console.log(`Consultando NVD (startIndex: ${startIndex}):`, url);

            const response = await fetchWithRetry(url, headers);
            
            totalResults = response.data.totalResults || 0;
            const vulnerabilities = response.data.vulnerabilities || [];
            
            console.log(`Recibidos ${vulnerabilities.length} de ${totalResults} CVEs en esta página.`);
            
            if (vulnerabilities.length === 0) {
                break;
            }

            const cves = vulnerabilities.map(item => {
                const cve = item.cve;
                return {
                    cveId: cve.id,
                    cvss:
                        cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
                        cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
                        cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? // Fallback to CVSS v2
                        null,
                    description:
                        cve.descriptions?.find(d => d.lang === "en")?.value || "",
                    published: cve.published,
                    modified: cve.lastModified
                };
            });

            // Persist to Database (Upsert)
            console.log(`Persistiendo ${cves.length} CVEs en base de datos...`);
            for (const cve of cves) {
                await prisma.cve.upsert({
                    where: { cveId: cve.cveId },
                    update: {
                        cvss: cve.cvss,
                        description: cve.description,
                        published: cve.published,
                        modified: cve.modified
                    },
                    create: {
                        cveId: cve.cveId,
                        cvss: cve.cvss,
                        description: cve.description,
                        published: cve.published,
                        modified: cve.modified
                    }
                });
            }

            // Merge into cves.json for compatibility
            const totalCatalogCount = mergeCVEsIntoJsonFile(cves);
            
            totalProcessed += cves.length;
            startIndex += vulnerabilities.length;

            console.log(`Progreso: ${totalProcessed} / ${totalResults} procesados. Total en catálogo JSON: ${totalCatalogCount}.`);

            // Courtesy delay before next request
            if (startIndex < totalResults) {
                console.log(`Respetando delay de cortesía de ${requestDelay}ms...`);
                await new Promise(resolve => setTimeout(resolve, requestDelay));
            }

        } while (startIndex < totalResults);

        // Save successful log
        const logData = {
            lastSync: endDate,
            records: totalProcessed,
            status: "SUCCESS"
        };
        fs.writeFileSync(LOG_FILE, JSON.stringify(logData, null, 2));

        console.log(`Sincronización finalizada con éxito. ${totalProcessed} CVEs procesados en total.`);
        return logData;

    } catch (error) {
        console.error("Error sincronizando NVD:", error.message);
        
        let errorDetails = error.message;
        if (error.response) {
            console.error("HTTP Status:", error.response.status);
            errorDetails = `NVD API responded with status ${error.response.status}`;
        } else if (error.request) {
            console.error("No response received from NVD (network issue)");
            errorDetails = "Network issue or timeout connecting to NVD API";
        }

        const logData = {
            lastSync: lastSync || new Date().toISOString(),
            status: "ERROR",
            error: errorDetails
        };

        try {
            fs.writeFileSync(LOG_FILE, JSON.stringify(logData, null, 2));
        } catch (fsErr) {
            console.error("No se pudo escribir el archivo de log:", fsErr.message);
        }

        return logData;
    } finally {
        await prisma.$disconnect();
    }
}

module.exports = syncCVEs;