# Retención del log de auditoría — Atrox (HU-008 / RNF-003)

Este documento describe la política de retención configurable del log de auditoría inmutable.

## Variable de configuración

| Variable | Descripción | Valor por defecto |
| :--- | :--- | :--- |
| `ATROX_AUDIT_RETENTION_DAYS` | Días que se conservan entradas de auditoría | `365` |
| `ATROX_AUDIT_LOG_PATH` | Ruta del archivo append-only (JSONL) | `data/audit.log` |
| `ATROX_AUDIT_SIGNING_KEY` | Llave HMAC-SHA256 para firmar entradas (**solo env**) | *(requerida)* |

## Comportamiento

1. Cada evento registrado incluye: **timestamp**, **usuario**, **acción** y **recurso**.
2. La entrada se firma con **HMAC-SHA256** antes de persistirse.
3. Al **arrancar el servicio**, se ejecuta `purge_expired()` y elimina entradas más antiguas que el periodo de retención.
4. La purga puede invocarse manualmente vía `AuditLogService.purge_expired()`.

## Generar llave de firma

```bash
python -c "from atrox.security.audit_signer import generate_signing_key; print(generate_signing_key())"
```

**Nunca** commitear el valor generado. Almacenarlo en el gestor de secretos del entorno.

## Recomendaciones por entorno

| Entorno | Retención sugerida | Notas |
| :--- | :--- | :--- |
| Desarrollo | 30 días | Suficiente para depuración local |
| Staging | 90 días | Validar integridad antes de producción |
| Producción | 365–730 días | Ajustar según política de cumplimiento interna |

## Cumplimiento y respaldo

- Realice **backups periódicos** del archivo `audit.log` en almacenamiento cifrado.
- La eliminación por retención es **irreversible** tras la purga.
- Ante investigaciones forenses, exporte el rango de fechas vía `GET /api/audit/logs?from=...&to=...` **antes** de que expire la retención.
- Verifique integridad periódicamente con `GET /api/audit/integrity`.

## Verificación

```bash
cd src/Backend
pytest tests/test_audit_log.py -v
```

## Eventos auditados automáticamente

| Acción | Origen | Recurso |
| :--- | :--- | :--- |
| `scan.submitted` | `POST /api/jobs` | `job:{uuid}` |
| `policy.updated` | `POST /api/audit/events` | Definido por cliente |
| *(custom)* | `POST /api/audit/events` | Definido por cliente |

## Checklist operativo

- [ ] `ATROX_AUDIT_SIGNING_KEY` configurada fuera del repositorio
- [ ] `ATROX_AUDIT_RETENTION_DAYS` alineada con política de la organización
- [ ] Backups del log programados
- [ ] Verificación de integridad periódica (`/api/audit/integrity`)
- [ ] Acceso a `/api/audit/logs` restringido (MFA — HU-018)
