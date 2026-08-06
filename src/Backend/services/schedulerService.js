const cron = require("node-cron");
const defaultRepos = require("../repositories/index");

const activeJobs = new Map();

/**
 * Presets cron comunes
 */
const PRESETS = {
    daily: "0 0 * * *",       // Todos los días a medianoche
    weekly: "0 0 * * 0",      // Todos los domingos a medianoche
    monthly: "0 0 1 * *"      // El primer día del mes a medianoche
};

/**
 * Normaliza y obtiene la expresión cron según el preset o la expresión directa.
 */
function resolveCronExpression(cronExpression, preset) {
    if (preset && PRESETS[preset.toLowerCase()]) {
        return PRESETS[preset.toLowerCase()];
    }
    return cronExpression;
}

/**
 * Cancela y remueve una tarea cron en memoria por su ID de regla.
 */
function unscheduleRule(ruleId) {
    if (activeJobs.has(ruleId)) {
        const task = activeJobs.get(ruleId);
        task.stop();
        activeJobs.delete(ruleId);
        return true;
    }
    return false;
}

/**
 * Ejecuta manualmente una regla en este instante, creando el escaneo (HU-009) y actualizando `lastRunAt`.
 */
async function executeRuleNow(ruleId, customRepos) {
    const repos = customRepos || defaultRepos;
    const rule = await repos.ScheduleRepository.getScheduleById(ruleId);
    if (!rule) {
        throw new Error(`Regla de agendamiento no encontrada (ID: ${ruleId})`);
    }

    // HU-009: Creación/Ejecución del escaneo
    const scan = await repos.ScanRepository.createScan({
        target: rule.target,
        startedAt: new Date()
    });

    const now = new Date();
    await repos.ScheduleRepository.updateLastRun(rule.id, now);

    return { rule, scan };
}

/**
 * Registra y programa una regla en node-cron si está activa.
 */
function scheduleRule(rule, customRepos) {
    const repos = customRepos || defaultRepos;
    unscheduleRule(rule.id);

    if (!rule.isActive) {
        return false;
    }

    const cronExpr = resolveCronExpression(rule.cronExpression, rule.preset);

    if (!cron.validate(cronExpr)) {
        console.warn(`[Scheduler] Expresión cron inválida para la regla ${rule.id}: "${cronExpr}"`);
        return false;
    }

    const task = cron.schedule(cronExpr, async () => {
        console.log(`[Scheduler] Ejecutando regla recurrente "${rule.name}" (${rule.id}) para target: ${rule.target}`);
        try {
            await executeRuleNow(rule.id, repos);
        } catch (err) {
            console.error(`[Scheduler] Error al ejecutar la regla ${rule.id}:`, err);
        }
    });

    activeJobs.set(rule.id, task);
    return true;
}

/**
 * Inicializa todas las reglas activas desde la base de datos.
 */
async function initScheduler(customRepos) {
    const repos = customRepos || defaultRepos;
    stopAllSchedulers();

    const schedules = await repos.ScheduleRepository.listSchedules();
    let scheduledCount = 0;

    for (const rule of schedules) {
        if (rule.isActive) {
            const success = scheduleRule(rule, repos);
            if (success) scheduledCount++;
        }
    }

    console.log(`[Scheduler] Inicializado. ${scheduledCount} reglas de escaneo recurrente activas.`);
    return scheduledCount;
}

/**
 * Detiene todas las tareas programadas activas.
 */
function stopAllSchedulers() {
    for (const [id, task] of activeJobs.entries()) {
        task.stop();
    }
    activeJobs.clear();
}

module.exports = {
    PRESETS,
    resolveCronExpression,
    initScheduler,
    scheduleRule,
    unscheduleRule,
    executeRuleNow,
    stopAllSchedulers,
    getActiveJobsCount: () => activeJobs.size
};
