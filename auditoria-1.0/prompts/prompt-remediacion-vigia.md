# Remediación de la auditoría de Vigía (bloque "antes de taggear v1.0.0")

## Tu rol

Sos el ingeniero que corrige los hallazgos de una auditoría ya hecha sobre
Vigía (`vigia-nids` 1.0.0, todavía **no** publicada). El reporte está en
`AUDITORIA-1.0.md`, en la raíz del repo (`Data/`). Leelo completo antes de
tocar nada: es la fuente de verdad sobre qué está mal, por qué, cómo se
reproduce y qué corrección se sugiere.

Tu objetivo es dejar la 1.0.0 en condiciones de publicarse: cada hallazgo del
bloque "Antes de taggear v1.0.0" corregido, con un test que falle antes del
arreglo y pase después, y con la documentación diciendo la verdad. No es
reescribir el proyecto: cambios mínimos, en el estilo del código existente.

Pensá cada corrección a fondo antes de escribirla. Para los hallazgos
científicos (SCI-*), la pregunta que manda es: **¿puede este cambio hacer que
Vigía diga "limpio" sobre un dataset que no lo está?** Si la respuesta es
"quizás", preferí saltar el check con un motivo honesto antes que dar un
resultado dudoso.

---

## Contexto que ya sabés (no lo re-derives)

- La auditoría encontró 50 hallazgos: 1 crítico, 8 altos, 18 medios, 17 bajos
  y 6 de información. 48 están confirmados con reproducción.
- Verifiqué a mano contra el código, y están bien descriptos: SEC-01 (glob con
  `dataset_id`), SCI-01 (`_as_datetime` devuelve el primer formato que
  interpreta algo), SCI-05 (descarte por cardinalidad en `single_feature`),
  SCI-06 (`accuracy < baseline + 0.05`), COR-04 (`len(tuple_cols) < 4`), COR-13
  (`r"uid"` sin borde), SCI-07 (`Infinity` en `_CSV_NULL_VALUES`).
- Los scripts de reproducción de la auditoría (`r01`…`r07`) se escribieron en
  un directorio temporal que probablemente ya no existe. El núcleo de cada
  reproducción está en la sección 3 del reporte (bloques "Reproducción") y en
  el anexo 7.2: usalo para escribir los tests.
- Línea base: 268 tests pasan, ruff y mypy limpios, cobertura 89,9 %
  (mínimo 85 %). El venv está en `vigia/.venv`.
- Convenciones del proyecto, que tenés que respetar:
  - Todo en español rioplatense, con voseo, en código, docstrings, mensajes,
    tests y commits.
  - Los docstrings y comentarios explican el **porqué**, no el qué. Imitá la
    densidad y el tono de los que ya existen.
  - Todo el texto de `src/` debe caber en cp1252 (hay un test que lo
    verifica: nada de `→`, `≥`, comillas tipográficas raras, emojis).
  - Línea máxima de 100 caracteres (ruff), con las excepciones de
    `pyproject.toml`.
  - Commits según el skill `commits-auditables`: **un commit por acción**,
    con la mayor granularidad posible sin romper el árbol, y un mensaje que
    explique el porqué (formato `tipo(ámbito): ...` como en el historial;
    mirá `git log --oneline -30`). Cada commit tiene que pasar la suite
    completa.

---

## Reglas (no negociables)

1. **Rama nueva:** antes del primer cambio, creá `git switch -c auditoria-1.0`
   desde `main`. Commiteá ahí.
2. **Nunca** hagas `git push`, `git tag`, ni toques `release.yml` para
   dispararlo; no publiques a PyPI; no cambies `version` en `pyproject.toml`
   ni `__version__`. Publicar es irreversible y lo decide Joshua.
3. **No descargues datasets** reales. Tests con datos sintéticos chicos,
   deterministas (semilla fija) y rápidos (que la suite no pase de ~90 s).
4. **Test primero:** para cada hallazgo, escribí el test que lo reproduce,
   corrélo y confirmá que **falla por el motivo correcto**; recién ahí
   corregí. Si un test nuevo pasa sin corregir nada, el hallazgo no se
   reprodujo: pará, investigá y reportalo en vez de "arreglar" algo que no
   está roto.
5. **Después de cada corrección:** `pytest -q`, `ruff check src tests`,
   `ruff format --check src tests`, `mypy src`. Todo verde antes de commitear.
6. **No amplíes el alcance.** Si encontrás un problema nuevo que no está en el
   reporte, anotalo para el resumen final; no lo arregles en esta tanda salvo
   que bloquee una corrección.
7. **Decisiones que no son tuyas** (están marcadas abajo con ⚠): no las tomes
   por tu cuenta. Preguntá con opciones concretas y una recomendación, y
   seguí con otros hallazgos mientras tanto.
8. No borres ni debilites tests existentes para que algo pase. Si un test
   existente codificaba el comportamiento incorrecto que estás corrigiendo,
   cambialo en el mismo commit y explicalo en el mensaje.

---

## Paso 0 — Preparación

1. Leé `AUDITORIA-1.0.md` completo, `vigia/docs/ARQUITECTURA.md`,
   `vigia/docs/CHECKS.md` y `vigia/docs/DERIVA.md`.
2. Arreglá TEST-02: `cd vigia && .venv/Scripts/python -m pip install -e ".[dev,ml,parquet,api]"`
   (los metadatos instalados dicen `vigia 0.1.0`). No es un cambio del repo.
3. Corré la línea base y confirmá 268 passed.
4. Creá la rama.

---

## Paso 1 — Correcciones, en este orden

El orden importa: primero lo que tiene causa raíz compartida y lo que
desbloquea los tests de los demás.

### 1.1 SEC-01 (crítica): `dataset_id` sin validar
- Tipo restringido en `api/models.py` (`^[0-9a-f]{32}$`) para `dataset_id` y
  `reference_id` en los tres modelos de petición, y también en los
  `job_id` de los path params.
- `storage.dataset_path` / `delete_dataset` sin `glob`: probar las extensiones
  de `VALID_EXTENSIONS` y verificar que el archivo resuelto quede dentro de
  `_STORAGE_DIR`. Defensa en profundidad: validar el formato también ahí, no
  solo en Pydantic.
- Test parametrizado: `*`, `"?"*32`, `[0-9a-f]*`, `../x`, `**/x` contra
  `/audits`, `/poison` y `/drift` → 422, y los datasets de otros siguen
  existiendo después.

### 1.2 COR-01 (alta): el contexto pierde `declared_roles`
- Causa raíz (DIS-01): `AuditContext` se reconstruye a mano en `cli.py` y dos
  veces en `benchmark.py`. Agregá un único método (p. ej.
  `AuditContext.with_df(df)` basado en `dataclasses.replace`) que copie todo
  salvo las cachés de `cached_property`, y usalo en los tres sitios.
  Verificá que `replace` no arrastre las cachés (viven en `__dict__`).
- Agregá `--profile` a `vigia fix` si es directo de hacer con lo que ya existe.
- Test de propiedad: con y sin columnas declaradas,
  `audit(fix(drop_duplicates))` no tiene `dup.exact`.

### 1.3 SCI-01, SCI-02, SCI-09: parser de tiempo
- `_as_datetime` en `checks/leakage.py` (y el mismo parser en
  `fixes/splits.py:30`, que tiene que ser **una sola función** compartida):
  elegir el formato que interpreta más valores, exigir que interprete casi
  toda la columna (umbral chico, documentado) y, si no, `CheckSkipped` con un
  motivo honesto que diga cuántos valores fallaron.
- Ambigüedad d/m vs m/d: si dos formatos interpretan el 100 % y dan órdenes
  distintos, saltar pidiendo el formato.
- ⚠ **Decisión:** ¿agregar una opción `time_format` (CLI `--time-format`,
  perfil y API)? Recomendación: sí, es la salida natural del skip por
  ambigüedad. Preguntá antes de agregar la opción pública.
- Distinguir en `leak.temporal` "split vacío después de descartar nulos" de
  "split no reconocido" (hoy da el motivo falso).
- SCI-09: `temporal_split` no puede mandar filas sin tiempo a "test";
  rechazar o marcarlas aparte, y decirlo en el `FixResult`.
- Tests: los casos 1, 2, 4 y 5 de la sección 3 del reporte.

### 1.4 SCI-04: `compare()` sobre test fijo
- Evaluar antes y después sobre las mismas filas de test (índice original;
  intersección si una corrección borra filas de test), o aplicar las
  correcciones solo a train. Elegí la que menos cambie la API pública y
  justificala en el docstring.
- Exponer `n_test` antes/después en `Comparison` y advertir si difieren.
- Test: `compare(ctx, ["quarantine_noise"])` sobre datos sin ruido no mejora
  el F1 más de un ε.

### 1.5 SCI-03: `drift.concept`
- ⚠ **Decisión:** (a) renombrar a `drift.covariate` (o similar), corregir
  `DERIVA.md` y el mensaje "no hace falta reentrenar" (2 h), o
  (b) implementar deriva de concepto real cuando el lote trae etiqueta:
  entrenar en la referencia y medir la caída de exactitud balanceada en el
  lote; sin etiqueta, saltar con ese motivo (≈1 día). Recomendación: (b) si
  hay tiempo, porque es lo que el producto promete; (a) como mínimo. Si
  renombrás, el id viejo cambia en el JSON: anotalo en el CHANGELOG.
- En cualquier caso, la CLI no puede decir "no hace falta reentrenar" cuando
  un check de deriva se saltó o no mide concepto.
- Test: el caso de etiqueta invertida (bloque N) no puede dar verde.

### 1.6 SCI-05: atajos en columnas continuas
- En `shortcut.single_feature`, las columnas de alta cardinalidad no se
  descartan: discretizar por cuantiles (p. ej. 20 bins) y aplicar la misma
  regla, o un árbol de profundidad baja con holdout. La opción por cuantiles
  no agrega dependencias y respeta el núcleo sin `[ml]`: preferila salvo que
  tengas una razón concreta.
- Cuidá los falsos positivos: la auditoría verificó que una columna de ruido
  con 25 % de valores únicos da 0,694. Agregá un test de control con ruido
  continuo puro que **no** debe reportar, además del de `x > 0.5` que sí.
- Corré `tests/unit/test_control_limpio.py`: el dataset de control tiene que
  seguir dando verde.

### 1.7 Arreglos chicos (un commit y un test cada uno)
- **COR-03:** `labels.conflict` con etiquetas nulas.
- **SCI-06:** `labels.noise` con exactitud balanceada o margen relativo
  (`(acc - base) / (1 - base)`). Test: 96 % benigno con 2 % de ruido → reporta
  ≈2 %.
- **SCI-08:** `dup.near` excluye solo las repeticiones
  (`is_first_distinct()`), no todas las copias.
- **COR-04:** `leak.session` exige las 5 columnas; agregá `src_port_col: Sport`
  al perfil `ctu-13` y `"sport"` a los candidatos de `src_port` (cuidado con
  `_EXACT_ONLY`).
- **COR-12:** `validity.constant` ignora nulos (`drop_nulls().n_unique() <= 1`)
  y lo mismo en `drop_constant` y en streaming.
- **COR-13:** `\buid\b` (revisá si `flow.?id` y otros patrones tienen el mismo
  problema).
- **COR-15:** el `version` por defecto de `run_audit` y
  `run_streaming_audit` sale de `vigia.__version__` (cuidado con el import
  circular).
- **COR-16:** `vigia fix --out` igual a la entrada → error claro.

### 1.8 SCI-07: infinitos del CSV
- No meter `Infinity`/`NaN` en `null_values`: que queden como `inf`/`nan`
  reales (leer como texto y convertir, o `schema_overrides` después de
  inferir). Verificá que `promoted_int_overrides` y el reintento cp1252 sigan
  funcionando, y que el modo streaming haga lo mismo.
- Test: CSV con `Infinity` → `validity.nan_inf` con `inf > 0` y severidad
  `high`.
- ⚠ **Decisión:** `RESULTADOS.md:73` y `CHECKS.md:329` afirman "2.867
  infinitos… Verificado", algo que el código actual no puede producir. No
  podés re-medirlo sin el dataset. Proponé el texto corregido (p. ej.
  "pendiente de re-medir con el lector corregido") y preguntá antes de
  cambiar un resultado publicado.

### 1.9 COR-02: `--streaming`
- Detección de columnas sobre `collect_schema()` con la misma `detect_column`,
  `strip` de nombres en el `LazyFrame` y `report.skipped["dup.cross_split"]`
  cuando falta el split.
- Test de equivalencia: para un CSV chico, `(check_id, affected_rows)` de los
  4 checks compartidos coincide entre eager y streaming.

### 1.10 COR-05 + COR-08: errores visibles
- `Report.errors` separado de `skipped`, `summary.n_errors` en el JSON, el
  reporte HTML y el panel los muestran aparte, y el semáforo no puede ser
  verde ni gris si hubo errores.
- La CLI: `except Exception` final con mensaje y código propio; 1 sigue
  significando "hay hallazgos que alcanzan `--fail-on`". Documentá los
  códigos en `ARQUITECTURA.md`/`USO.md`.
- ⚠ **Decisión:** agregar `errors` al JSON cambia el contrato que
  ARQUITECTURA.md llama estable. Recomendación: hacerlo ahora, antes de la
  1.0, junto con `"schema_version": "1"` (DIS-02), porque después cuesta un
  cambio de versión mayor. Preguntá.
- Actualizá `web/src/types.ts` y los componentes si cambia el JSON, y
  verificá con `npm run build` y `npm run lint` en `vigia/web`.

### 1.11 CI-01: release seguro
- `release.yml`: `permissions: contents: read` a nivel de workflow
  (`id-token: write` solo en `publish`), tests + ruff + mypy antes de
  construir, verificación de que el tag `vX.Y.Z` coincide con `pyproject.toml`
  y con `vigia.__version__`.
- Versión en un solo lugar: `__version__` leído con
  `importlib.metadata.version("vigia-nids")` (con un fallback razonable para
  cuando el paquete no está instalado).
- Fijar las actions por SHA (comentá al lado qué versión es cada SHA).
  Obtené los SHA reales con `gh api` o `git ls-remote`, **no los inventes**;
  si no tenés red o `gh`, dejalo anotado como pendiente.
- Aprovechá para CI-04 (lista de inclusión del sdist) y CI-05 (classifier
  acorde a 1.0): son de una línea y afectan lo que se publica.
- Construí wheel y sdist en un directorio temporal y verificá contenido y
  tamaño.

### 1.12 DOC-01 y DOC-02: que la documentación diga la verdad
- README: dejar de afirmar que cubre los diez P0 o decir exactamente qué falta
  de R5, R6, R7 y R8 (y `labels.window`). Pasá los faltantes a la lista de
  límites conocidos de `PLAN.md`.
- Corregir los detalles de DOC-02 (xxhash, `dup.near` "una sola columna",
  comentario del compose, USO.md sobre el corte de la subida, DERIVA.md).
- Actualizar en README/PLAN/CHECKS el número de tests y cualquier conteo que
  cambie (checks, ids, códigos de salida).
- `CHANGELOG.md`: todo bajo `[Unreleased]` en las secciones
  Corregido/Cambiado/Agregado, explicando el impacto para quien usa la
  herramienta. ⚠ No muevas nada a `[1.0.0]` ni cambies la fecha: Joshua decide
  si la 1.0.0 sale con estos cambios dentro o cómo numerar.

---

## Fuera de alcance de esta tanda

El bloque "Antes de desplegar" (SEC-02 a SEC-06, SEC-09, SEC-12, COR-06, COR-07,
COR-09, tope de trabajos, caducidad de reportes) y el bloque "Después"
(PERF-01, CI-02, CI-03, TEST-01, R6/R7/R8, el resto de bajas). No los toques.
Sí podés hacer SEC-11 (`hmac.compare_digest`) si ya estás en
`api/security.py` por SEC-01: es una línea.

---

## Entregable

1. La rama `auditoria-1.0` con un commit por corrección, todos con la suite
   verde.
2. Al final, `pytest -q --cov=src`, `ruff check`, `ruff format --check`,
   `mypy src`, `npm run build` y `npm run lint` en verde, y la cobertura sin
   bajar de la línea base (89,9 %).
3. Re-corré las reproducciones núcleo del anexo 7.2 del reporte y mostrá que
   ahora dan el resultado correcto.
4. Agregá al final de `AUDITORIA-1.0.md` una sección **"8. Estado de la
   remediación"** con una tabla `ID | estado (corregido / pendiente /
   decisión pendiente) | commit | test que lo cubre`, más la lista de
   problemas nuevos que encontraste sin arreglar.
5. En el chat, solo: qué quedó corregido, qué decisiones ⚠ necesitan respuesta
   de Joshua, qué falta para poder taggear la v1.0.0, y el comando para ver
   los commits (`git log --oneline main..auditoria-1.0`).
