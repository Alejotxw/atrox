const { PrismaClient } = require("@prisma/client");
const { PrismaBetterSqlite3 } = require("@prisma/adapter-better-sqlite3");

// Factory function to initialize repositories with an optional custom Prisma instance.
// This allows dependency injection of a test Prisma client in integration tests.
function createRepositories(prismaInstance) {
    let prisma = prismaInstance;

    function getPrisma() {
        if (!prisma) {
            const dbUrl = process.env.DATABASE_URL || "file:./dev.db";
            const adapter = new PrismaBetterSqlite3({ url: dbUrl });
            prisma = new PrismaClient({ adapter });
        }
        return prisma;
    }

    const ScanRepository = {
        async createScan({ target, startedAt }) {
            const db = getPrisma();
            return await db.scan.create({
                data: {
                    target,
                    status: "PENDING",
                    startedAt: startedAt || new Date()
                }
            });
        },

        async updateScanStatus(scanId, status, finishedAt) {
            const db = getPrisma();
            return await db.scan.update({
                where: { id: scanId },
                data: {
                    status,
                    finishedAt: finishedAt || new Date()
                }
            });
        },

        async getScanWithDetails(scanId) {
            const db = getPrisma();
            return await db.scan.findUnique({
                where: { id: scanId },
                include: {
                    assets: {
                        include: {
                            findings: true
                        }
                    },
                    reports: true
                }
            });
        },

        async listScans() {
            const db = getPrisma();
            return await db.scan.findMany({
                orderBy: { startedAt: "desc" }
            });
        }
    };

    const AssetRepository = {
        async createAsset({ ip, hostname, os, scanId }) {
            const db = getPrisma();
            return await db.asset.create({
                data: {
                    ip,
                    hostname,
                    os,
                    scanId
                }
            });
        },

        async getAssetsByScan(scanId) {
            const db = getPrisma();
            return await db.asset.findMany({
                where: { scanId },
                include: {
                    findings: true
                }
            });
        }
    };

    const FindingRepository = {
        async createFinding({ cveId, severity, description, assetId }) {
            const db = getPrisma();
            return await db.finding.create({
                data: {
                    cveId,
                    severity,
                    description,
                    assetId
                }
            });
        },

        async getFindingsByScan(scanId) {
            const db = getPrisma();
            return await db.finding.findMany({
                where: {
                    asset: {
                        scanId: scanId
                    }
                },
                include: {
                    asset: true
                }
            });
        },

        async getFindingsByAsset(assetId) {
            const db = getPrisma();
            return await db.finding.findMany({
                where: { assetId }
            });
        }
    };

    const ReportRepository = {
        async createReport({ filePath, scanId }) {
            const db = getPrisma();
            return await db.report.create({
                data: {
                    filePath,
                    scanId
                }
            });
        },

        async getReportsByScan(scanId) {
            const db = getPrisma();
            return await db.report.findMany({
                where: { scanId }
            });
        }
    };

    return {
        get prisma() {
            return getPrisma();
        },
        ScanRepository,
        AssetRepository,
        FindingRepository,
        ReportRepository
    };
}

const defaultRepos = createRepositories();

module.exports = {
    createRepositories,
    ...defaultRepos
};
