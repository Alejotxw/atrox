const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { PrismaClient } = require("@prisma/client");
const { PrismaBetterSqlite3 } = require("@prisma/adapter-better-sqlite3");

// Define test database path (relative to where prisma.config.ts resolves from)
const TEST_DB_PATH = "./test.db";
const TEST_DB_URL = `file:${TEST_DB_PATH}`;
process.env.DATABASE_URL = TEST_DB_URL;

// Ensure database schema is provisioned applying the versioned migrations (same as CI)
console.log("Aplicando migraciones versionadas a la base de datos de prueba SQLite...");
try {
    execSync("npx prisma migrate deploy", {
        env: { ...process.env, DATABASE_URL: TEST_DB_URL },
        cwd: path.join(__dirname, ".."),
        stdio: "pipe"
    });
    console.log("Migraciones aplicadas exitosamente a la base de datos de prueba.");
} catch (err) {
    console.error("Error al aplicar migraciones a la base de datos de pruebas:", err.stdout?.toString() || err.message);
    process.exit(1);
}

// Initialize repositories with the test Prisma client using the adapter
const { createRepositories } = require("../repositories/index");
const testAdapter = new PrismaBetterSqlite3({ url: TEST_DB_URL });
const prismaTestClient = new PrismaClient({ adapter: testAdapter });
const { ScanRepository, AssetRepository, FindingRepository, ReportRepository } = createRepositories(prismaTestClient);

test.after(async () => {
    // Close connection
    await prismaTestClient.$disconnect();

    // Clean up test database files
    console.log("Limpiando archivos de base de datos de prueba...");
    const dbFile = path.join(__dirname, "../test.db");
    const dbJournalFile = path.join(__dirname, "../test.db-journal");

    try {
        if (fs.existsSync(dbFile)) {
            fs.unlinkSync(dbFile);
        }
        if (fs.existsSync(dbJournalFile)) {
            fs.unlinkSync(dbJournalFile);
        }
        console.log("Limpieza completada.");
    } catch (err) {
        console.error("Error limpiando archivos de prueba:", err.message);
    }
});

test("HU-006: Integración y Relaciones del Modelo de Persistencia", async (t) => {
    await t.test("Debería crear un escaneo, agregar activos, reportes y hallazgos y mantener las relaciones", async () => {
        // 1. Create a Scan
        const scan = await ScanRepository.createScan({
            target: "192.168.1.0/24"
        });
        assert.ok(scan.id);
        assert.strictEqual(scan.target, "192.168.1.0/24");
        assert.strictEqual(scan.status, "PENDING");

        // 2. Add an Asset to the Scan
        const asset = await AssetRepository.createAsset({
            ip: "192.168.1.5",
            hostname: "laptop-test.local",
            os: "Linux Ubuntu",
            scanId: scan.id
        });
        assert.ok(asset.id);
        assert.strictEqual(asset.ip, "192.168.1.5");
        assert.strictEqual(asset.scanId, scan.id);

        // 3. Add a Finding to the Asset
        const finding = await FindingRepository.createFinding({
            cveId: "CVE-2026-0001",
            severity: "High",
            description: "Dummy test vulnerability",
            assetId: asset.id
        });
        assert.ok(finding.id);
        assert.strictEqual(finding.cveId, "CVE-2026-0001");
        assert.strictEqual(finding.assetId, asset.id);

        // 4. Add a Report to the Scan
        const report = await ReportRepository.createReport({
            filePath: "/reports/scan_192.168.1.0_24.pdf",
            scanId: scan.id
        });
        assert.ok(report.id);
        assert.strictEqual(report.filePath, "/reports/scan_192.168.1.0_24.pdf");
        assert.strictEqual(report.scanId, scan.id);

        // 5. Update Scan Status
        const updatedScan = await ScanRepository.updateScanStatus(scan.id, "COMPLETED");
        assert.strictEqual(updatedScan.status, "COMPLETED");
        assert.ok(updatedScan.finishedAt);

        // 6. Retrieve Scan Details and Verify Hierarchy
        const scanDetails = await ScanRepository.getScanWithDetails(scan.id);
        assert.strictEqual(scanDetails.assets.length, 1);
        assert.strictEqual(scanDetails.reports.length, 1);
        assert.strictEqual(scanDetails.assets[0].findings.length, 1);
        assert.strictEqual(scanDetails.assets[0].findings[0].cveId, "CVE-2026-0001");
    });
});

test("HU-006: Rendimiento de Consultas sobre Gran Dataset (< 3 segundos)", async (t) => {
    await t.test("Debería consultar hallazgos de un escaneo con 10,000 registros en menos de 3 segundos", async () => {
        // 1. Create a baseline Scan
        const scan = await ScanRepository.createScan({
            target: "performance-target.local"
        });

        // 2. Seed a heavy dataset of 50 assets and 200 findings each (10,000 findings total)
        console.log("Sembrando dataset de prueba (50 activos, 10,000 hallazgos en total)...");
        
        const assetPromises = [];
        for (let i = 0; i < 50; i++) {
            assetPromises.push(
                AssetRepository.createAsset({
                    ip: `10.0.0.${i}`,
                    hostname: `server-perf-${i}.local`,
                    os: "Windows Server 2022",
                    scanId: scan.id
                })
            );
        }
        const assets = await Promise.all(assetPromises);

        // Batch insert findings for performance in seeding
        const findingsData = [];
        for (const asset of assets) {
            for (let j = 0; j < 200; j++) {
                findingsData.push({
                    cveId: `CVE-2026-PERF-${j}`,
                    severity: j % 4 === 0 ? "Critical" : j % 3 === 0 ? "High" : "Medium",
                    description: `Vulnerabilidad de prueba sembrada número ${j} para activo ${asset.ip}`,
                    assetId: asset.id
                });
            }
        }

        // Use Prisma createMany to seed rapidly
        await prismaTestClient.finding.createMany({
            data: findingsData
        });
        console.log("Dataset de prueba sembrado exitosamente.");

        // 3. Measure query duration for FindingRepository.getFindingsByScan(scanId)
        console.log("Midiendo tiempo de consulta de hallazgos por escaneo...");
        const startTime = Date.now();
        
        const findings = await FindingRepository.getFindingsByScan(scan.id);
        
        const duration = Date.now() - startTime;
        console.log(`Consulta finalizada. Registros obtenidos: ${findings.length}. Duración: ${duration} ms.`);

        // 4. Assertions
        assert.strictEqual(findings.length, 10000);
        assert.ok(duration < 3000, `La consulta tardó ${duration}ms, lo cual excede el límite de 3000ms.`);
    });
});
