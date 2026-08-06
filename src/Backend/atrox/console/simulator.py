"""Demo simulada de logs de escaneo para DoD de HU-020."""

from __future__ import annotations

import asyncio

from atrox.console.bus import ScanLogBus
from atrox.console.models import LogSeverity


async def run_simulated_scan(bus: ScanLogBus, target: str) -> None:
    """Emite una secuencia típica NMAP/NUCLEI hacia el bus (sin herramientas reales)."""
    steps: list[tuple[str, LogSeverity, str, float]] = [
        ("INFO", LogSeverity.INFO, "Starting AI-Pentest Framework v1.0", 0.15),
        ("QUEUE", LogSeverity.INFO, f"Demo scan enqueued for target={target}", 0.2),
        ("NMAP", LogSeverity.INFO, f"Scanning target: {target}", 0.35),
        ("NMAP", LogSeverity.INFO, "Discovered open port 80/tcp (http)", 0.25),
        ("NMAP", LogSeverity.INFO, "Discovered open port 443/tcp (https)", 0.2),
        ("NMAP", LogSeverity.WARNING, "Discovered open port 3306/tcp (mysql)", 0.25),
        ("NUCLEI", LogSeverity.INFO, "Loading templates for web vulnerabilities...", 0.3),
        (
            "NUCLEI",
            LogSeverity.CRITICAL,
            "SQL Injection found on /login.php (parameter 'user')",
            0.35,
        ),
        (
            "NUCLEI",
            LogSeverity.CRITICAL,
            "Apache Path Traversal (CVE-2021-41773) in /cgi-bin/",
            0.3,
        ),
        (
            "NUCLEI",
            LogSeverity.WARNING,
            "Default credentials allowed on MySQL Port 3306",
            0.25,
        ),
        ("OLLAMA", LogSeverity.INFO, "Feeding findings to correlation engine...", 0.2),
        ("INFO", LogSeverity.INFO, "Demo scan completed", 0.1),
    ]

    for module, severity, message, delay in steps:
        await bus.emit(module, message, severity=severity)
        await asyncio.sleep(delay)
