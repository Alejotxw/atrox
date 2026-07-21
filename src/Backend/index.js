const express = require("express");
const cors = require("cors");
const syncCVEs = require("./services/nvdService");
const { ScheduleRepository, ScanRepository } = require("./repositories/index");
const schedulerService = require("./services/schedulerService");

const app = express();

app.use(cors());
app.use(express.json());

// Sincronización NVD CVEs
app.get("/sync-cves", async (req, res) => {
    await syncCVEs();
    res.json({ message: "Sincronización ejecutada" });
});

// --- RUTAS HU-011: Programación de escaneos recurrentes ---

// CRUD 1: Listar todas las reglas de agendamiento
app.get("/api/schedules", async (req, res) => {
    try {
        const schedules = await ScheduleRepository.listSchedules();
        res.json(schedules);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CRUD 2: Crear una nueva regla de agendamiento
app.post("/api/schedules", async (req, res) => {
    try {
        const { name, target, cronExpression, preset, isActive } = req.body;
        if (!name || !target) {
            return res.status(400).json({ error: "Nombre y Objetivo (target) son requeridos" });
        }

        const cronExpr = schedulerService.resolveCronExpression(cronExpression, preset);
        if (!cronExpr) {
            return res.status(400).json({ error: "Debe proporcionar un preset válido o una expresión Cron" });
        }

        const newRule = await ScheduleRepository.createSchedule({
            name,
            target,
            cronExpression: cronExpr,
            preset,
            isActive: isActive !== undefined ? isActive : true
        });

        if (newRule.isActive) {
            schedulerService.scheduleRule(newRule);
        }

        res.status(201).json(newRule);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CRUD 3: Obtener regla por ID
app.get("/api/schedules/:id", async (req, res) => {
    try {
        const rule = await ScheduleRepository.getScheduleById(req.params.id);
        if (!rule) return res.status(404).json({ error: "Regla no encontrada" });
        res.json(rule);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CRUD 4: Actualizar una regla
app.put("/api/schedules/:id", async (req, res) => {
    try {
        const { name, target, cronExpression, preset, isActive } = req.body;
        const cronExpr = schedulerService.resolveCronExpression(cronExpression, preset);

        const updated = await ScheduleRepository.updateSchedule(req.params.id, {
            name,
            target,
            cronExpression: cronExpr,
            preset,
            ...(isActive !== undefined ? { isActive } : {})
        });

        if (updated.isActive) {
            schedulerService.scheduleRule(updated);
        } else {
            schedulerService.unscheduleRule(updated.id);
        }

        res.json(updated);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Criterio de Aceptación 3: Pausar / Reanudar regla
app.patch("/api/schedules/:id/toggle", async (req, res) => {
    try {
        const rule = await ScheduleRepository.getScheduleById(req.params.id);
        if (!rule) return res.status(404).json({ error: "Regla no encontrada" });

        const newStatus = !rule.isActive;
        const updated = await ScheduleRepository.toggleScheduleStatus(rule.id, newStatus);

        if (updated.isActive) {
            schedulerService.scheduleRule(updated);
        } else {
            schedulerService.unscheduleRule(updated.id);
        }

        res.json(updated);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// CRUD 5: Eliminar regla
app.delete("/api/schedules/:id", async (req, res) => {
    try {
        schedulerService.unscheduleRule(req.params.id);
        await ScheduleRepository.deleteSchedule(req.params.id);
        res.json({ message: "Regla eliminada exitosamente" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Criterio de Aceptación 2 & DoD: Ejecución inmediata de escaneo vía regla
app.post("/api/schedules/:id/run", async (req, res) => {
    try {
        const result = await schedulerService.executeRuleNow(req.params.id);
        res.json({
            message: "Escaneo recurrente ejecutado exitosamente",
            scan: result.scan,
            rule: result.rule
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Listar escaneos generados (HU-009)
app.get("/api/scans", async (req, res) => {
    try {
        const scans = await ScanRepository.listScans();
        res.json(scans);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Servidor de Atrox iniciado en puerto ${PORT}`);
    try {
        await schedulerService.initScheduler();
    } catch (err) {
        console.error("Error al inicializar el agendador de tareas:", err);
    }
});

module.exports = app;