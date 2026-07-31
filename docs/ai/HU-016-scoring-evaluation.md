# Evaluación del Agente de Scoring de Confianza — HU-016

**Trazabilidad:** RF-005 · RNF-004
**Módulo:** `src/Backend/atrox/ai/agents/scoring/`
**Dataset:** `src/Backend/tests/fixtures/scoring_dataset.py`
**Test que reproduce esta medición:** `src/Backend/tests/test_scoring_precision.py`

---

## Qué mide el agente

`POST /api/ai/scoring/score` recibe un `VulnFinding` y devuelve un score de confianza 0-100 (`ConfidenceScoreResult.score`). Un hallazgo se marca `probable_fp=true` cuando `score < threshold`, donde `threshold` viene de `ATROX_FP_SCORE_THRESHOLD` (default **40**) y puede sobre-escribirse por request.

El score es 100% heurístico (no hay LLM conectado en este proyecto — verificado antes de implementar: ningún cliente `ChatOpenAI`/`ChatAnthropic` existe en `atrox/`, ver también ADR-004 para el mismo hallazgo aplicado a HU-015). Las señales usadas (`atrox/ai/agents/scoring/rules.py`):

| Señal | Efecto | Justificación |
| :--- | :--- | :--- |
| Severidad reportada por Nuclei | Score base (20–70) | Proxy inicial de impacto |
| `extracted_results` no vacío | +15 | Evidencia concreta extraída (ej. output de un comando, contenido de archivo) |
| Tag `cve` o `cve` en `template_id` | +10 | Vulnerabilidad con identificador público conocido |
| Cada referencia externa | +5 (tope +15) | Validación externa documentada |
| Tags de fingerprinting (`tech`, `fingerprint`, `detect`, `panel`, `ssl`, `tls`) | −20 | Estos templates suelen ser detección de tecnología, no confirmación de vulnerabilidad explotable |
| Sin `description` | −10 | Falta contexto que sustente el hallazgo |

## Dataset de prueba etiquetado

22 hallazgos construidos manualmente (`tests/fixtures/scoring_dataset.py`), 11 verdaderos positivos (`is_true_positive=True`) y 11 falsos positivos (`is_true_positive=False`), inspirados en patrones reales de Nuclei (CVEs conocidos con PoC, vs. templates de fingerprinting sin evidencia).

Se incluyeron **a propósito 2 casos difíciles** para que la métrica no sea un 100% trivial (lo cual habría indicado un dataset demasiado fácil de separar, no una evaluación honesta):

- **TP difícil** (`auth-bypass-logic-flaw`): una vulnerabilidad de lógica de negocio (IDOR) confirmada manualmente por un analista, pero el template Nuclei solo la reporta como `detect` de severidad `low`, sin `extracted_results`. La heurística no puede distinguir esto de un falso positivo real — **limitación conocida y documentada**, no un bug.
- **FP difícil** (`cve-generic-banner-match`): un template mal calibrado que asigna tag `cve` y severidad `high` a partir de un simple banner grab (`Server: nginx/1.18.0`), con una referencia NVD que no corresponde realmente a una explotación confirmada. La heurística lo sobrestima.

## Resultado medido (umbral por defecto = 40)

Matriz de confusión sobre la decisión "¿escalar este hallazgo?" (positivo = `probable_fp=false`):

| | Predicho: escalar (real) | Predicho: descartar (probable_fp) |
| :--- | :---: | :---: |
| **Real: vulnerabilidad confirmada (11)** | TP = 10 | FN = 1 (`auth-bypass-logic-flaw`) |
| **Real: falso positivo (11)** | FP = 1 (`cve-generic-banner-match`) | TN = 10 |

- **Precisión** = TP / (TP + FP) = 10 / 11 = **0.909**
- **Recall** = TP / (TP + FN) = 10 / 11 = **0.909**
- **Exactitud** = (TP + TN) / 22 = **0.909**

Umbral mínimo aceptado en CI: **≥ 0.85** (`MIN_ACCEPTED_PRECISION` en `test_scoring_precision.py`). El valor medido (0.909) supera ese mínimo con margen; se fijó 0.85 y no 0.909 exacto para no acoplar el test a la tercera cifra decimal ante cambios menores de redondeo, mientras que `test_confusion_matrix_matches_documented_evaluation` sí fija los conteos exactos (10/1/10/1) para detectar cualquier cambio de comportamiento.

## Cómo reproducir esta medición

```bash
cd src/Backend
pytest tests/test_scoring_precision.py -v
```

## Limitaciones conocidas

1. **Heurística, no aprendizaje automático real.** El catálogo de señales es curado manualmente; no generaliza a categorías de vulnerabilidad no contempladas explícitamente (ej. una técnica de evasión nueva sin `cve`/evidencia clara recibirá un score bajo por defecto, sesgando hacia `probable_fp=true`).
2. **Recall limitado en hallazgos de baja severidad sin evidencia extraída**, incluso si son reales (ver caso `auth-bypass-logic-flaw`). Un SOC que use `probable_fp` como filtro automático de descarte (en vez de solo priorización) puede perder este tipo de hallazgos — se recomienda usarlo para *priorizar*, no para *descartar automáticamente sin revisión humana*.
3. **Vulnerable a templates mal calibrados** que inflan artificialmente severidad/tags (ver caso `cve-generic-banner-match`).
4. Si en el futuro se conecta un LLM real (ADR-002), esta evaluación debe repetirse: el comportamiento del scoring cambiaría de determinista/explicable a probabilístico, y el dataset aquí documentado sigue siendo válido como regresión mínima a mantener.
