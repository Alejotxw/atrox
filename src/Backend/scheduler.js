const cron = require("node-cron");
const syncCVEs = require("./services/nvdService");

cron.schedule("0 2 * * *", async () => {
    console.log("Ejecutando sincronización NVD...");
    await syncCVEs();
});

console.log("Scheduler iniciado");