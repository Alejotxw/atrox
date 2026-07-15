-- CreateTable
CREATE TABLE "Cve" (
    "cveId" TEXT NOT NULL PRIMARY KEY,
    "cvss" REAL,
    "description" TEXT NOT NULL,
    "published" TEXT NOT NULL,
    "modified" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateIndex
CREATE INDEX "Cve_cveId_idx" ON "Cve"("cveId");

-- CreateIndex
CREATE INDEX "Finding_cveId_idx" ON "Finding"("cveId");
