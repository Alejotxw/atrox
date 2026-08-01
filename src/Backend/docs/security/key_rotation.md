# Rotación de llaves maestras — Atrox (HU-007 / ADR-003)

Este documento describe el procedimiento operativo para rotar la llave maestra de cifrado (`ATROX_ENCRYPTION_MASTER_KEY`) sin comprometer la confidencialidad ni la integridad de los datos en reposo.

## Principios

- La llave maestra **nunca** se almacena en el repositorio, imágenes Docker ni logs.
- Solo se inyecta vía **variable de entorno** o gestor de secretos (Vault, AWS Secrets Manager, etc.).
- La pérdida de la llave implica **pérdida irreversible** de los datos cifrados con ella.
- El algoritmo en uso es **AES-256-GCM** (`cryptography`).

## Generar una nueva llave

Desde el entorno de despliegue (no commitear el resultado):

```bash
python -c "from atrox.security.encryption import generate_master_key; print(generate_master_key())"
```

Copie el valor generado al gestor de secretos y asígnelo como `ATROX_ENCRYPTION_MASTER_KEY`.

Formatos aceptados:

- **Base64** de 32 bytes (recomendado)
- **Hexadecimal** de 64 caracteres (32 bytes)

## Rotación sin downtime (re-cifrado)

### 1. Preparación

1. Genere la **llave nueva** (`KEY_NEW`).
2. Mantenga acceso a la **llave actual** (`KEY_OLD`) durante la migración.
3. Tome backup cifrado de la base de datos / almacenamiento.

### 2. Migración de datos

Para cada registro con campos cifrados (`v`, `alg`, `payload`):

1. Descifre con `KEY_OLD` usando `EncryptionService(KEY_OLD)`.
2. Cifre el plaintext resultante con `KEY_NEW` usando `EncryptionService(KEY_NEW)`.
3. Persista el nuevo blob cifrado.
4. Verifique integridad con muestreo aleatorio (descifrar con `KEY_NEW`).

Pseudocódigo:

```python
old_svc = EncryptionService(decode_master_key(KEY_OLD))
new_svc = EncryptionService(decode_master_key(KEY_NEW))

plaintext = old_svc.decrypt_from_dict(stored_blob)
new_blob = new_svc.encrypt_to_dict(plaintext)
# persistir new_blob
```

### 3. Cutover

1. Actualice `ATROX_ENCRYPTION_MASTER_KEY` en el gestor de secretos a `KEY_NEW`.
2. Reinicie/despliegue los servicios del backend.
3. Confirme que lecturas y escrituras funcionan con la llave nueva.

### 4. Retención de llave anterior

- Conserve `KEY_OLD` en el gestor de secretos **solo** el tiempo necesario para rollback o auditoría forense.
- Elimine `KEY_OLD` de forma segura una vez confirmada la migración completa.

## Rotación de emergencia (llave comprometida)

1. Revoke inmediato de `KEY_OLD` en todos los entornos.
2. Genere `KEY_NEW` y aplique cutover.
3. Re-cifre todos los datos históricos accesibles (si aún existen descifrables con backup + KEY_OLD).
4. Registre el incidente en el log de auditoría (HU-008).
5. Notifique a SysAdmins y Directores de TI según política interna.

## Verificación post-rotación

```bash
cd src/Backend
pytest tests/test_encryption.py -v
```

Confirme además que:

- Ningún campo sensible aparece en texto plano en BD/archivos.
- Descifrado con llave incorrecta produce `DecryptionError`.
- La aplicación arranca solo con `ATROX_ENCRYPTION_MASTER_KEY` válida cuando el módulo de cifrado está activo.

## Checklist operativo

- [ ] Llave generada fuera del repositorio
- [ ] Llave almacenada en gestor de secretos
- [ ] Backup previo a migración
- [ ] Re-cifrado completado y verificado
- [ ] Servicios reiniciados con llave nueva
- [ ] Llave anterior revocada/eliminada
- [ ] Incidente documentado (si aplica)
