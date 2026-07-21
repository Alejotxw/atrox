const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { PrismaClient } = require("@prisma/client");
const { PrismaBetterSqlite3 } = require("@prisma/adapter-better-sqlite3");

// Define test database path for schedule tests
const TEST_SCHEDULE_DB = "./schedule_test.db";
const TEST_SCHEDULE_URL = `file:${TEST_SCHEDULE_DB}`;
process.env.DATABASE_URL = TEST_SCHEDULE_URL;

// Ensure database schema is pushed to the test database
console.log("Aprovisionando base de datos de pruebas para HU-011...");
try {
    execSync("npx prisma db push --accept-data-loss", {
        env: { ...process.env, DATABASE_URL: TEST_SCHEDULE_URL },
        cwd: path.join(__dirname, ".."),
        stdio: "pipe"
    });
    console.log("Base de datos de pruebas HU-011 aprovisionada.");
} catch (err) {
    console.error("Error aprovisionando la BD de prueba HU-011:", err.stdout?.toString() || err.message);
    process.exit(1);
}

// Initialize repositories and test client
const { createRepositories } = require("../repositories/index");
const schedulerService = require("../services/schedulerService");

const testAdapter = new PrismaBetterSqlite3({ url: TEST_SCHEDULE_URL });
const prismaTestClient = new PrismaClient({ adapter: testAdapter });
const testRepos = createRepositories(prismaTestClient);
const { ScheduleRepository, ScanRepository } = testRepos;

test.after(async () => {
    schedulerService.stopAllSchedulers();
    await prismaTestClient.$disconnect();

    const dbFile = path.join(__dirname, "../prisma/schedule_test.db");
    const dbJournalFile = path.join(__dirname, "../prisma/schedule_test.db-journal");

    try {
        if (fs.existsSync(dbFile)) fs.unlinkSync(dbFile);
        if (fs.existsSync(dbJournalFile)) fs.unlinkSync(dbJournalFile);
    } catch (err) {
        console.error("Error limpiando BD de prueba HU-011:", err.message);
    }
});

test("HU-011: CRUD de reglas de scheduling y Presets Cron", async (t) => {
    // Limpieza de datos previa
    await prismaTestClient.scheduleRule.deleteMany();
    let createdRuleId;


    await t.test("1. Debería crear una regla de agendamiento con preset diario", async () => {
        const rule = await ScheduleRepository.createSchedule({
            name: "Escaneo Diario Servidores Web",
            target: "192.168.10.0/24",
            cronExpression: schedulerService.PRESETS.daily,
            preset: "daily",
            isActive: true
        });

        assert.ok(rule.id, "La regla creada debe poseer un ID");
        assert.strictEqual(rule.name, "Escaneo Diario Servidores Web");
        assert.strictEqual(rule.target, "192.168.10.0/24");
        assert.strictEqual(rule.cronExpression, "0 0 * * *");
        assert.strictEqual(rule.preset, "daily");
        assert.strictEqual(rule.isActive, true);

        createdRuleId = rule.id;
    });

    await t.test("2. Debería listar las reglas de agendamiento existentes", async () => {
        const rules = await ScheduleRepository.listSchedules();
        assert.ok(Array.isArray(rules));
        assert.strictEqual(rules.length, 1);
        assert.strictEqual(rules[0].id, createdRuleId);
    });

    await t.test("3. Debería obtener una regla por su ID", async () => {
        const rule = await ScheduleRepository.getScheduleById(createdRuleId);
        assert.ok(rule);
        assert.strictEqual(rule.name, "Escaneo Diario Servidores Web");
    });

    await t.test("4. Debería actualizar una regla existente (cambiar objetivo y preset semanal)", async () => {
        const updated = await ScheduleRepository.updateSchedule(createdRuleId, {
            name: "Escaneo Semanal DMZ",
            target: "10.0.0.0/16",
            cronExpression: schedulerService.PRESETS.weekly,
            preset: "weekly"
        });

        assert.strictEqual(updated.name, "Escaneo Semanal DMZ");
        assert.strictEqual(updated.target, "10.0.0.0/16");
        assert.strictEqual(updated.cronExpression, "0 0 * * 0");
        assert.strictEqual(updated.preset, "weekly");
    });

    await t.test("5. Debería eliminar una regla de agendamiento", async () => {
        const tempRule = await ScheduleRepository.createSchedule({
            name: "Regla Temporal",
            target: "172.16.0.1",
            cronExpression: "0 12 * * *",
            preset: "custom"
        });

        await ScheduleRepository.deleteSchedule(tempRule.id);
        const deleted = await ScheduleRepository.getScheduleById(tempRule.id);
        assert.strictEqual(deleted, null);
    });
});

test("HU-011: Posibilidad de pausar y reanudar reglas de scheduling", async (t) => {
    let ruleId;

    await t.test("Debería pausar una regla activa y luego reanudarla", async () => {
        // Crear regla activa
        const rule = await ScheduleRepository.createSchedule({
            name: "Escaneo Mensual de Subredes",
            target: "192.168.1.0/24",
            cronExpression: schedulerService.PRESETS.monthly,
            preset: "monthly",
            isActive: true
        });
        ruleId = rule.id;

        // Programar en scheduler
        const scheduled = schedulerService.scheduleRule(rule, testRepos);
        assert.strictEqual(scheduled, true);
        assert.strictEqual(schedulerService.getActiveJobsCount(), 1);

        // Pausar regla
        const pausedRule = await ScheduleRepository.toggleScheduleStatus(ruleId, false);
        assert.strictEqual(pausedRule.isActive, false);

        // Desprogramar en scheduler service
        schedulerService.unscheduleRule(ruleId);
        assert.strictEqual(schedulerService.getActiveJobsCount(), 0);

        // Reanudar regla
        const resumedRule = await ScheduleRepository.toggleScheduleStatus(ruleId, true);
        assert.strictEqual(resumedRule.isActive, true);

        // Reprogramar en scheduler
        const reScheduled = schedulerService.scheduleRule(resumedRule, testRepos);
        assert.strictEqual(reScheduled, true);
        assert.strictEqual(schedulerService.getActiveJobsCount(), 1);
    });
});

test("HU-011: Ejecución automática crea escaneo vía HU-009 y actualiza lastRunAt", async (t) => {
    await t.test("Ejecutar regla desencadena la creación de un nuevo escaneo en ScanRepository", async () => {
        // Crear regla para prueba de ejecución
        const rule = await ScheduleRepository.createSchedule({
            name: "Escaneo Automatizado de Laboratorio",
            target: "10.10.10.5",
            cronExpression: "* * * * *",
            preset: "custom",
            isActive: true
        });

        // Ejecutar la regla mediante el servicio de agendamiento
        const result = await schedulerService.executeRuleNow(rule.id, testRepos);

        // Verificaciones
        assert.ok(result.scan, "Se debe haber retornado el escaneo creado");
        assert.ok(result.scan.id, "El escaneo creado debe poseer ID");
        assert.strictEqual(result.scan.target, "10.10.10.5");
        assert.strictEqual(result.scan.status, "PENDING");

        // Verificar persistencia en ScanRepository (HU-009 integration)
        const scanFromDb = await ScanRepository.getScanWithDetails(result.scan.id);
        assert.ok(scanFromDb);
        assert.strictEqual(scanFromDb.target, "10.10.10.5");

        // Verificar que la regla actualizó lastRunAt
        const updatedRule = await ScheduleRepository.getScheduleById(rule.id);
        assert.ok(updatedRule.lastRunAt);
        assert.ok(new Date(updatedRule.lastRunAt) <= new Date());
    });
});

test("HU-011 Definition of Done: Demostración en Entorno de Laboratorio", async (t) => {
    await t.test("Inicialización del agendador y despacho de múltiples reglas activas", async () => {
        // Limpiar schedulers activos y base de datos de prueba
        schedulerService.stopAllSchedulers();
        await prismaTestClient.scheduleRule.deleteMany();

        // Crear 3 reglas (2 activas, 1 pausada)
        await ScheduleRepository.createSchedule({
            name: "Regla Lab 1",
            target: "192.168.1.100",
            cronExpression: "0 * * * *",
            isActive: true
        });
        await ScheduleRepository.createSchedule({
            name: "Regla Lab 2",
            target: "192.168.1.101",
            cronExpression: "0 0 * * *",
            isActive: true
        });
        await ScheduleRepository.createSchedule({
            name: "Regla Lab 3 (Pausada)",
            target: "192.168.1.102",
            cronExpression: "0 0 * * 0",
            isActive: false
        });

        const activeCount = await schedulerService.initScheduler(testRepos);
        assert.strictEqual(activeCount, 2, "Debe haber activado exactamente 2 reglas en memoria");
        assert.strictEqual(schedulerService.getActiveJobsCount(), 2);
    });
});

