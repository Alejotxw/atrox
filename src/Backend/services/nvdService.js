const axios = require("axios");
const fs = require("fs");
const path = require("path");

const CVE_FILE = path.join(__dirname, "../data/cves.json");
const LOG_FILE = path.join(__dirname, "../data/sync-log.json");

async function syncCVEs() {
    try {

        let lastSync = null;

        if (fs.existsSync(LOG_FILE)) {
            const content = fs.readFileSync(LOG_FILE, "utf8");

            if (content.trim()) {
                const log = JSON.parse(content);
                lastSync = log.lastSync || null;
            }
        }

        const endDate = new Date().toISOString();

        let url = "https://services.nvd.nist.gov/rest/json/cves/2.0";

        const params = new URLSearchParams();

        // Limitar resultados para pruebas
        params.append("resultsPerPage", "10");

        if (lastSync) {
            params.append("lastModStartDate", lastSync);
            params.append("lastModEndDate", endDate);
        }

        url += `?${params.toString()}`;

        console.log("Consultando:", url);

        const response = await axios.get(url, {
            timeout: 30000,
            headers: {
                "User-Agent": "Atrox-CVE-Sync/1.0"
            }
        });

        const vulnerabilities =
            response.data.vulnerabilities || [];

        const cves = vulnerabilities.map(item => {

            const cve = item.cve;

            return {
                cveId: cve.id,
                cvss:
                    cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
                    null,
                description:
                    cve.descriptions?.find(
                        d => d.lang === "en"
                    )?.value || "",
                published: cve.published,
                modified: cve.lastModified
            };
        });

        fs.writeFileSync(
            CVE_FILE,
            JSON.stringify(cves, null, 2)
        );

        fs.writeFileSync(
            LOG_FILE,
            JSON.stringify(
                {
                    lastSync: endDate,
                    records: cves.length,
                    status: "SUCCESS"
                },
                null,
                2
            )
        );

        console.log(
            `Sincronizados ${cves.length} CVEs`
        );

    } catch (error) {

        console.error("Error sincronizando NVD");

        if (error.response) {
            console.error(
                "HTTP Status:",
                error.response.status
            );
        }

        console.error(
            "Detalle:",
            error.message
        );

        fs.writeFileSync(
            LOG_FILE,
            JSON.stringify(
                {
                    lastSync: new Date().toISOString(),
                    status: "ERROR",
                    error: error.message
                },
                null,
                2
            )
        );
    }
}

module.exports = syncCVEs;