const express = require("express");
const syncCVEs = require("./services/nvdService");

const app = express();

app.get("/sync-cves", async (req, res) => {

    await syncCVEs();

    res.json({
        message: "Sincronización ejecutada"
    });
});

app.listen(3000, () => {
    console.log("Servidor iniciado");
});