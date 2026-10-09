# Auditoría integral de Vigía (vigia-nids 1.0.0)

Fecha: 04/10/2026 · Alcance: `vigia/` en `main` (`35da75a`) · Modo: solo lectura
(ningún archivo del repo se modificó salvo este reporte; sin tags, pushes ni publicaciones).

> El historial de commits de este proyecto no se publica: este repositorio parte de
> un solo commit. Los hashes que se citan en este archivo son del historial
> original y no se pueden consultar aquí; los tests de cada corrección sí están
> en `vigia/tests/`.

---

## 1. Resumen ejecutivo

**¿Se puede publicar la 1.0.0 en PyPI? — No todavía.** El núcleo es sólido (268 tests verdes,
métricas de deriva idénticas a scipy, duplicados exactos correctos), pero hay resultados científicos
incorrectos y reproducibles en casos comunes que contradicen lo que la documentación promete:
`leak.temporal` descarta en silencio filas cuyo tiempo no interpreta y da "sin hallazgo" con fuga real
(SCI-01) o da un **crítico falso** con fechas m/d/Y (SCI-02); `drift.concept` no puede ver deriva de
concepto y el comando dice "no hace falta reentrenar" (SCI-03); `compare()` mide antes y después sobre
conjuntos de prueba distintos y `quarantine_noise` infla el F1 15 puntos (SCI-04); `vigia fix` no borra
los duplicados que `audit` reporta cuando hay columnas declaradas (COR-01). Además `release.yml`
publica sin correr tests ni verificar que el tag coincida con la versión (CI-01), y la 1.0 es
irreversible. Ninguno es caro de corregir: ~3–4 días.

**¿Se puede desplegar la API en internet? — No.** Además de lo anterior: `dataset_id` llega sin
validar a `Path.glob`, lo que permite leer o **borrar** datasets ajenos y alcanzar archivos fuera del
directorio de subidas (SEC-01, crítico); las subidas huérfanas no se borran nunca y no hay límite de
subidas, así que el disco se llena (SEC-02); el límite de tamaño no corta el stream (SEC-05); y el
botón "Ver el reporte HTML" del panel da 401 siempre que hay clave (COR-07). Sumado a los tres cambios
que `PLAN.md` ya reconoce (tope de trabajos, caducidad de reportes, `VIGIA_MAX_UPLOAD_MB`).

**Conteo:** 1 crítica · 8 altas · 18 medias · 17 bajas · 6 info (50 hallazgos; 48 CONFIRMADOS, 2 PROBABLES).

---

## 2. Tabla de hallazgos

| ID | Sev. | Estado | Título | Ubicación |
|---|---|---|---|---|
| SEC-01 | Crítica | CONFIRMADO | `dataset_id` sin validar llega a `glob`: leer/borrar datasets ajenos y archivos fuera del almacenamiento | `api/storage.py:134-146`, `api/models.py:28-49` |
| SCI-01 | Alta | CONFIRMADO | `leak.temporal` descarta en silencio las filas cuyo tiempo no se interpreta: fuga real → "sin hallazgo" | `checks/leakage.py:48-61,82-85` |
| SCI-02 | Alta | CONFIRMADO | Fechas m/d/Y se interpretan como d/m/Y: crítico falso del 100 % sin fuga | `checks/leakage.py:54` |
| SCI-03 | Alta | CONFIRMADO | `drift.concept` no usa la etiqueta: no detecta deriva de concepto y el semáforo da verde | `drift/checks.py:283-396`, `docs/DERIVA.md:29` |
| SCI-04 | Alta | CONFIRMADO | `compare()` evalúa antes y después sobre test distintos; `quarantine_noise` infla F1 +0,15 | `benchmark.py:204-257` |
| COR-01 | Alta | CONFIRMADO | `vigia fix` y `compare()` pierden `declared_roles`: `drop_duplicates` no borra lo que `dup.exact` reporta | `cli.py:306-320`, `benchmark.py:220-256` |
| SCI-05 | Alta | CONFIRMADO | `shortcut.single_feature` descarta toda columna continua: un atajo por umbral perfecto no se reporta | `checks/shortcuts.py:115-120` |
| SEC-02 | Alta | CONFIRMADO | Subidas huérfanas nunca se borran y `POST /datasets` no tiene límite: agotamiento de disco | `api/storage.py:30-42`, `api/routes.py:45-55`, `docker-compose.yml` |
| CI-01 | Alta | CONFIRMADO | `release.yml` publica sin tests, sin verificar tag = versión, actions por tag mutable | `.github/workflows/release.yml` |
| COR-02 | Media | CONFIRMADO | `--streaming` no detecta etiqueta/split ni normaliza nombres; omite `dup.cross_split` sin listarlo; crashea con CSV de CIC | `core/streaming.py:128-130,271-336` |
| COR-03 | Media | CONFIRMADO | `labels.conflict` crashea con etiquetas nulas (`TypeError`) | `checks/labels.py:71-73` |
| SCI-06 | Media | CONFIRMADO | `labels.noise` no puede correr si la clase mayoritaria es ≥ 95 % | `checks/label_noise.py:167-174` |
| SCI-07 | Media | CONFIRMADO | `Infinity`/`NaN` del CSV se leen como nulos: los infinitos de CICFlowMeter salen como "low, 0 infinitos" | `io/readers.py:92` |
| COR-04 | Media | CONFIRMADO | `leak.session` corre con 4 de 5 columnas (contradice la doc); en CTU-13 falta el puerto de origen | `checks/leakage.py:203` |
| SCI-08 | Media | CONFIRMADO | `dup.near` excluye todas las copias de un duplicado exacto: sus casi-duplicados son invisibles | `checks/duplicates.py:298,311` |
| COR-05 | Media | CONFIRMADO | Un check que crashea por bug se reporta igual que uno saltado por diseño | `core/engine.py:45-48`, `core/findings.py:111-128` |
| SEC-03 | Media | CONFIRMADO | Limitador: sin clave se evade rotando la cabecera; con clave el cupo es global; `_hits` crece sin límite | `api/security.py:59-93` |
| SEC-04 | Media | CONFIRMADO | Parquet comprimido (×3.419) se descomprime entero para validarlo, en el hilo del event loop | `api/storage.py:117-131` |
| SEC-05 | Media | CONFIRMADO | El límite de subida no corta el stream: el cuerpo completo se escribe en disco antes del 413 | `api/storage.py:62-100`, `docs/USO.md:189-192` |
| COR-06 | Media | CONFIRMADO | La API rechaza (415) CSV en cp1252 que la CLI acepta (día de ataques web de CIC-IDS2017) | `api/storage.py:124` |
| COR-07 | Media | CONFIRMADO | El enlace "Ver el reporte HTML" del panel da 401 siempre que hay clave | `web/src/pages/Result.tsx:145`, `web/src/api.ts` |
| COR-08 | Media | CONFIRMADO | Errores inesperados salen con código 1, el mismo que "hay hallazgos" | `cli.py:175-214` |
| PERF-01 | Media | CONFIRMADO | `dup.near` (77 s), `shortcut.single_feature` (14 s) y PSI/KS en Python puro (~70 s/40 col) | `checks/duplicates.py`, `checks/shortcuts.py`, `drift/metrics.py:47-61,93-117` |
| CI-02 | Media | CONFIRMADO | CI sin `permissions`, sin lint del front, sin wheel ni prueba sin `[ml]`, sin `pip-audit` | `.github/workflows/ci.yml` |
| CI-03 | Media | PROBABLE | `polars>=1.0` sin techo: la semántica de `hash_rows`/inferencia puede cambiar | `pyproject.toml` |
| DOC-01 | Media | CONFIRMADO | Requisitos P0 que el README da por cumplidos están incompletos (R5, R6, R7, R8) | `README.md:15-17`, `vigia.md` §6 |
| TEST-01 | Media | CONFIRMADO | Huecos: `cli.py` 44 %, sin tests de los casos de Fase 1 ni de equivalencia eager/streaming | `tests/unit/` |
| COR-09 | Baja | CONFIRMADO | Deep links del panel (`/resultado/:id`, `/deriva`) dan 404 al recargar | `api/app.py:102-104` |
| COR-10 | Baja | CONFIRMADO | El comando que arma "Corregir" usa `dataset:<id>` como ruta: no se puede ejecutar | `web/src/pages/Fix.tsx` |
| COR-11 | Baja | CONFIRMADO | Claves React duplicadas (`key={f.check_id}`) cuando un check emite varios hallazgos | `web/src/components/Findings.tsx`, `Fix.tsx` |
| COR-12 | Baja | CONFIRMADO | `validity.constant` no ve una columna constante con nulos (el comentario dice lo contrario) | `checks/validity.py:148-150` |
| COR-13 | Baja | CONFIRMADO | El patrón `uid` sin borde marca "ruido" como identificador y lo saca de los modelos auxiliares | `checks/shortcuts.py:26` |
| COR-14 | Baja | CONFIRMADO | `category_col` del perfil `unsw-nb15` se ignora en silencio: `attack_cat` queda como característica | `__init__.py:73-111`, `profiles/unsw-nb15.yaml` |
| COR-15 | Baja | CONFIRMADO | `run_audit`/`run_streaming_audit` registran `vigia_version="0.1.0"` por defecto | `core/engine.py:17`, `core/streaming.py:279` |
| COR-16 | Baja | CONFIRMADO | `vigia fix --out` igual al archivo de entrada lo sobrescribe ("el original nunca se toca") | `cli.py:341-342` |
| SCI-09 | Baja | CONFIRMADO | `temporal_split` manda a "test" las filas sin tiempo interpretable | `fixes/splits.py:40-45` |
| SEC-06 | Baja | PROBABLE | Errores se devuelven con el texto crudo de la excepción | `api/jobs.py:126-128`, `api/storage.py:125-130` |
| SEC-07 | Baja | CONFIRMADO | Los reportes de la API exponen filas e IPs reales (§17 promete anonimizarlas) | `core/context.py:129-132`, `vigia.md:882` |
| SEC-08 | Baja | CONFIRMADO | `VITE_API_KEY` se embebe en el JS público y no se advierte | `web/src/api.ts` |
| SEC-09 | Baja | CONFIRMADO | Contenedor: sin digest, `curl` en runtime, `web/dist` escribible por el usuario de la app, sin `--proxy-headers` | `Dockerfile` |
| SEC-10 | Baja | CONFIRMADO | `load_profile` acepta `../` en el id del perfil (solo CLI/SDK local) | `profiles/__init__.py:37` |
| CI-04 | Baja | CONFIRMADO | El sdist incluye todo el árbol de trabajo (local: 98 MiB de `node_modules`) | `pyproject.toml` |
| DOC-02 | Baja | CONFIRMADO | Documentación desactualizada o falsa en detalles (xxhash, `dup.near`, compose, CORS) | varios |
| PERF-02 | Baja | CONFIRMADO | La validación de subidas carga el archivo entero en RAM solo para contar filas | `api/storage.py:117-131` |
| SEC-11 | Info | CONFIRMADO | Clave comparada con `!=` (riesgo de timing despreciable, pero barato de cerrar) | `api/security.py:53` |
| SEC-12 | Info | CONFIRMADO | CORS con `allow_credentials=True` innecesario | `api/app.py:84-90` |
| CI-05 | Info | CONFIRMADO | Classifier "3 - Alpha" en 1.0.0; versión duplicada a mano | `pyproject.toml`, `__init__.py:23` |
| DIS-01 | Info | CONFIRMADO | Lógica duplicada: listas de splits, eager/streaming, reconstrucción de `AuditContext` en 3 lugares | varios |
| DIS-02 | Info | CONFIRMADO | El JSON no lleva versión de esquema | `core/findings.py:135-152` |
| TEST-02 | Info | CONFIRMADO | El venv de desarrollo tiene metadatos viejos (`vigia 0.1.0`) | `vigia/.venv` |

---

## 3. Detalle de cada hallazgo

### SEC-01 — `dataset_id` sin validar llega a `Path.glob` (Crítica, CONFIRMADO)

**Ubicación.** `src/vigia/api/storage.py:134-140` (`dataset_path`), `:143-146` (`delete_dataset`);
`src/vigia/api/models.py:28-49` (`dataset_id: str` sin restricción); `api/jobs.py:98-108` (borrado al terminar).

**Defecto.** El id que el cliente manda en el JSON se interpola en un patrón: `_STORAGE_DIR.glob(f"{dataset_id}.*")`.
Los metacaracteres de glob (`*`, `?`, `[...]`) y los segmentos `..` se interpretan. El mismo valor se guarda
en `Job.dataset_ids` y, al terminar el trabajo, `delete_dataset` hace `unlink` de **todo** lo que el
patrón encuentre.

**Escenario de fallo.** Un cliente (cualquiera, si la API corre sin clave; cualquiera con la clave
compartida, si no) lanza un trabajo con un `dataset_id` comodín: el trabajo audita un dataset de otro
usuario y, al terminar, borra todos los datasets pendientes del directorio. Con segmentos `..` el patrón
alcanza archivos fuera del directorio de subidas que el proceso pueda leer (y, al terminar el trabajo,
borrar). El aislamiento entre clientes, que hoy descansa en que los UUID no se adivinan, desaparece.

**Reproducción.** Prueba local del patrón exacto que usa el código (`r05_glob.py`, sin servidor), idéntica
en Python 3.11.9 y 3.13.5:

```
'*'                -> ['vigia_api_x/aaaa1111.csv', 'vigia_api_x/bbbb2222.parquet']
'????????'         -> [ambos]
'[ab]*'            -> [ambos]
'../secreto'       -> ['vigia_api_x/../secreto.csv']
'../otro_dir/dato' -> ['vigia_api_x/../otro_dir/dato.csv']
```

**Impacto.** Confidencialidad (datasets de tráfico de red de terceros) e integridad/disponibilidad (borrado
masivo). Bloquea el despliegue; también la 1.0, porque `vigia serve` viaja en el paquete.

**Corrección.** Validar en el modelo y no usar glob:

```python
# models.py
from pydantic import constr
DatasetId = constr(pattern=r"^[0-9a-f]{32}$")
class AuditRequest(BaseModel):
    dataset_id: DatasetId
    ...
# storage.py: guardar {dataset_id: Path} en un dict al subir, o
for suffix in VALID_EXTENSIONS:
    p = (_STORAGE_DIR / f"{dataset_id}{suffix}").resolve()
    if p.parent == _STORAGE_DIR.resolve() and p.is_file():
        return p
```

**Test.** `test_dataset_id_con_comodines_da_422` parametrizado con `*`, `?`*32, `[0-9a-f]*`, `../x`, `**/x`
contra `/audits`, `/poison` y `/drift`, verificando además que los datasets de otros siguen existiendo.

### SCI-01 — `leak.temporal` descarta en silencio las filas cuyo tiempo no interpreta (Alta, CONFIRMADO)

**Ubicación.** `checks/leakage.py:48-61` (`_as_datetime`), `:82-85` (`drop_nulls`).

**Defecto.** `_as_datetime` prueba formatos con `strict=False` y devuelve **el primero que interpreta al
menos un valor** (`if parsed.null_count() < s.len()`). Las filas que quedaron nulas se descartan después
con `drop_nulls()` y el hallazgo no lo menciona.

**Escenario de fallo.** Entrenamiento con `2017-07-10..19 10:00:00`; 90 % del test posterior
(`2017-07-21..29`) y 10 % anterior al entrenamiento pero escrito `1/7/2017 9:00` (mezcla de formatos, común
al concatenar archivos de distintos días o extractores). 905 de 945 tiempos se interpretan; las 40 filas que
filtran se descartan.

**Reproducción** (`r03_temporal.py`, caso 4):
```
parseadas: 905 de 945
leak.temporal -> [] {}          # sin hallazgo, sin skip: el reporte puede salir verde
```
Si **todo** el test está en el formato no interpretado, el check se salta con un motivo falso:
`"no se reconocen splits de entrenamiento y prueba en 'split'"` (los splits sí se reconocen).

**Impacto.** Es exactamente el modo de fallo que Vigía existe para evitar: "limpio" con fuga real.

**Corrección.** Exigir que se interprete (casi) toda la columna; si no, saltar con un mensaje honesto, o
reportar las filas descartadas:

```python
best = max(candidatos, key=lambda p: s.len() - p.null_count())
n_fail = best.null_count() - s.null_count()
if n_fail / s.len() > 0.001:
    raise CheckSkipped(f"{n_fail:,} valores de '{col}' no se pudieron interpretar como fecha")
```
y en el check, distinguir "split vacío tras descartar nulos" de "split no reconocido".

**Test.** El caso 4 de `r03_temporal.py` debe dar hallazgo o skip, nunca `[]`.

### SCI-02 — fechas m/d/Y interpretadas como d/m/Y (Alta, CONFIRMADO)

**Ubicación.** `checks/leakage.py:54` (orden de formatos: `None`, `%d/%m/%Y %H:%M:%S`, …, `%m/%d/%Y %H:%M`).

**Escenario de fallo.** Train 1–10 de julio y test 1–5 de agosto, escritos `07/DD/2017 10:00:00`. Se lee
"7 de enero…7 de octubre" contra "8 de enero…8 de mayo".

**Reproducción** (`r03_temporal.py`, caso 2):
```
train min/max: 2017-01-07 .. 2017-10-07   test min/max: 2017-01-08 .. 2017-05-08
leak.temporal -> [('critical', '100.0% de las filas de prueba son anteriores al fin del entrenamiento')]
```
Con días > 12 (caso 1) el entrenamiento no se interpreta y el check se salta con el mismo motivo falso que
en SCI-01. `temporal_split` usa el mismo parser (`fixes/splits.py:30`) y produce un split temporal **al revés**.

**Impacto.** Un crítico falso hace que el usuario "corrija" un split correcto.

**Corrección.** Detectar la ambigüedad: si un formato d/m y uno m/d interpretan ambos el 100 % y dan órdenes
distintos, saltar pidiendo el formato; aceptar `time_format` como opción (CLI, perfil y API).

**Test.** Los casos 1 y 2 deben dar skip con "formato ambiguo", no crítico.

### SCI-03 — `drift.concept` no detecta deriva de concepto (Alta, CONFIRMADO)

**Ubicación.** `drift/checks.py:283-396`; `docs/DERIVA.md:25-29,74-86`.

**Defecto.** El check es validación adversaria sobre las **características** (`comunes = numeric_cols`);
nunca usa la etiqueta. Mide covariate shift, lo mismo que `drift.feature`. La doc lo presenta como el check
de "la relación entre características y etiqueta".

**Escenario / reproducción** (`r04`, bloque N): misma distribución de X, etiqueta invertida (`x1+x2>0` era
ATTACK y pasa a ser BENIGN), proporciones iguales:
```
hallazgos de deriva: NINGUNO | semaforo: verde
```
y la CLI imprime "El lote se parece a la referencia: no hace falta reentrenar."

**Impacto.** Afirmación falsa sobre lo que se detecta, con un verde en el peor caso de deriva.

**Corrección.** O renombrarlo (`drift.covariate` / "distinguibles") y corregir DERIVA.md, o implementar
concepto de verdad cuando el lote trae etiqueta: entrenar en la referencia y medir la caída de exactitud
balanceada sobre el lote (o comparar `P(y|x)` por bins). Sin etiqueta, saltarlo con ese motivo.

**Test.** El caso N debe producir un hallazgo de concepto (o un skip explícito si no hay etiqueta).

### SCI-04 — `compare()` cambia el conjunto de prueba (Alta, CONFIRMADO)

**Ubicación.** `benchmark.py:204-257`.

**Defecto.** Las correcciones se aplican al dataset entero y `evaluate` vuelve a partir por la columna de
split: filas de **test** borradas o apartadas no se evalúan en el "después". `quarantine_noise` aparta
justamente las filas que un modelo auxiliar no predice bien, así que el F1 sube por construcción.

**Reproducción** (`r04`, bloque L; datos sin defectos, clases solapadas):
```
F1 macro: 0.7555 -> 0.9082 (+0.1527) | n_test antes: 1810 despues: 1516
```

**Impacto.** El README presenta `compare` como la medida de "cuánto del rendimiento era real"; con esta
corrección mide lo contrario. El mismo efecto, menor, ocurre con `drop_duplicates` (quita duplicados internos
del test).

**Corrección.** Fijar el conjunto de evaluación: aplicar las correcciones solo a las filas de train (o a
todas, pero evaluar ambas corridas sobre la intersección de filas de test, identificadas con un índice
original). Reportar `n_test` antes/después y advertir si difieren.

**Test.** `compare(ctx, ["quarantine_noise"])` sobre datos sin ruido no debe mejorar el F1 más de un ε.

### COR-01 — `vigia fix` y `compare()` pierden los roles declarados (Alta, CONFIRMADO)

**Ubicación.** `cli.py:306-320`, `benchmark.py:220-234,242-256` (se reconstruye `AuditContext` sin
`declared_roles`).

**Defecto.** USO.md:41-48 dice que las columnas declaradas quedan fuera del hash "de `drop_duplicates`". En la
cadena de `fix`, el contexto nuevo no las trae, así que la deduplicación las incluye.

**Reproducción** (`r04`, bloque K):
```
audit --time-col Timestamp -> 90.00% de las filas son duplicados exactos
drop_duplicates: 23 filas duplicadas eliminadas, 277 conservadas
re-audit tras fix -> 89.17% de las filas son duplicados exactos
```

**Impacto.** La receta documentada "auditar, corregir, volver a auditar" no converge; y `compare()` deja
duplicados cruzados en el "después", inflando el F1 corregido.

**Corrección.** Un único `ctx.replace(df=...)` (`dataclasses.replace`) que copie todo salvo las cachés, usado
en los tres sitios. Agregar `--profile` a `vigia fix`.

**Test.** Propiedad: para todo dataset, `audit(fix(drop_duplicates))` no tiene `dup.exact`, con y sin
columnas declaradas.

### SCI-05 — `shortcut.single_feature` ignora las columnas continuas (Alta, CONFIRMADO)

**Ubicación.** `checks/shortcuts.py:115-120`; `docs/CHECKS.md:196-199`.

**Defecto.** Toda columna con más del 30 % de valores únicos se descarta "porque la cubre
`shortcut.identifier`", pero ese check solo mira el **nombre**. Una característica continua que separa por
umbral (el atajo típico de un árbol) no se reporta nunca.

**Reproducción** (`r02`, bloque B): `flow_iat_min ~ U(0,1)`, etiqueta `x > 0.5`:
```
findings: ['1 columna(s) identificadora(s) presentes como características']   # por "ruido", ver COR-13
```
Ningún hallazgo de atajo sobre la columna que predice el 100 %.

**Impacto.** R5 pide "la precisión de un modelo entrenado solo con ella". Falso negativo en el caso que más
importa para NIDS (tasas, tiempos, tamaños).

**Corrección.** Para columnas de alta cardinalidad, discretizar por cuantiles (p. ej. 20 bins) y aplicar la
misma regla, o entrenar un árbol de profundidad 2–3 con holdout (idealmente sobre el split del dataset).

**Test.** El bloque B debe producir `shortcut.single_feature` crítico sobre `flow_iat_min`.

### SEC-02 — Subidas huérfanas y sin límite (Alta, CONFIRMADO)

**Ubicación.** `api/storage.py:30-42`; `api/routes.py:45-55`; `docker-compose.yml` (volumen `vigia_uploads`,
`TMPDIR=/data/uploads`).

**Defecto.** Un archivo solo se borra cuando un trabajo que lo usa termina, o con `atexit`. Una subida que
nunca se usa queda para siempre mientras el proceso viva; tras SIGKILL/OOM (lo esperable con 5 GiB por
auditoría en 8 GB) el volumen persiste y `_remove_stale_empty_dirs` solo borra directorios **vacíos**.
`POST /datasets` no pasa por el limitador.

**Escenario.** N subidas de 500 MB sin lanzar trabajos llenan el disco; con `restart: unless-stopped` y un OOM
en el medio, la basura sobrevive a los reinicios. El comentario del compose ("este volumen no crece sin límite")
es falso. Esto **no** está en la lista de PLAN.md (que solo pide bajar `VIGIA_MAX_UPLOAD_MB`).

**Corrección.** TTL de subidas (p. ej. 1 h sin uso → borrar, tarea periódica), cuota total del directorio,
limpieza al arrancar de directorios `vigia_api_*` de otros PID, y rate limit también en `/datasets`.

**Test.** Subida sin trabajo + avanzar el reloj → el archivo desaparece.

### CI-01 — `release.yml` publica sin red de seguridad (Alta, CONFIRMADO)

**Ubicación.** `.github/workflows/release.yml`.

**Defecto.** El job `build` no corre `pytest`/`ruff`/`mypy`; no compara `${GITHUB_REF_NAME#v}` con
`pyproject.toml` ni con `vigia.__version__` (duplicadas a mano); `actions/*@v4` y
`pypa/gh-action-pypi-publish@release/v1` son tags mutables; no hay `permissions:` a nivel workflow (el job
`build` hereda los permisos por defecto del token).

**Impacto.** Publicar es irreversible: un tag mal puesto o un commit roto sube a PyPI sin que nada lo frene.

**Corrección.**
```yaml
permissions: {contents: read}
jobs:
  build:
    steps:
      - uses: actions/checkout@<sha>
      - run: pip install -e ".[dev,ml,parquet,api]" && pytest -q && ruff check src tests && mypy src
      - run: |
          v=$(python -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
          test "v$v" = "$GITHUB_REF_NAME"
          test "$(python -c 'import vigia;print(vigia.__version__)')" = "$v"
```
Fijar las actions por SHA. Leer `__version__` con `importlib.metadata.version("vigia-nids")`.

### COR-02 — `--streaming` diverge del modo normal (Media, CONFIRMADO)

**Ubicación.** `core/streaming.py:128-130,271-336`.

**Defecto.** (a) No hay `detect_column`: sin `--label-col`/`--split-col`, `dup.exact` se calcula sin etiqueta y
`dup.cross_split` devuelve `[]` **sin** aparecer en `skipped`; (b) no se aplica `strip_column_names`, así que
`--label-col Label` (o `--profile cic-ids-2017`) sobre un CSV de CICFlowMeter (`" Label"`) crashea.

**Reproducción** (`r04`, bloque M, mismo CSV):
```
eager:     [('dup.class_ratio', 976), ('dup.cross_split', 1000), ('dup.exact', 976)]
streaming: [('dup.exact', 952)]   | dup.cross_split ni en hallazgos ni en skipped
streaming --label-col Label FALLA: ColumnNotFoundError ... Did you mean " Label"?
```
**Corrección.** Detectar columnas sobre `collect_schema()` con la misma función, renombrar con `strip` en el
`LazyFrame`, y registrar `report.skipped["dup.cross_split"]` cuando falte el split.
**Test.** Para un CSV chico, el conjunto `(check_id, affected_rows)` de eager y streaming debe coincidir en los
4 checks compartidos.

### COR-03 — `labels.conflict` crashea con etiquetas nulas (Media, CONFIRMADO)

**Ubicación.** `checks/labels.py:71-73` (`" / ".join(row["labels"])` con un `None`).
**Reproducción** (`r02`, bloque A): `skipped: {'labels.conflict': 'error interno: TypeError: sequence item 0: expected str instance, NoneType found'}`.
**Impacto.** En CIC-IDS2017 hay 288.602 filas sin etiqueta; basta que una comparta características con una
etiquetada para perder el check (y, sin otros hallazgos, ver COR-05).
**Corrección.** Excluir nulos antes de agrupar (`drop_nulls("label")`) y reportarlos aparte, o
`" / ".join(map(str, ...))`. **Test.** El bloque A no debe producir `error interno`.

### SCI-06 — `labels.noise` imposible con clase mayoritaria ≥ 95 % (Media, CONFIRMADO)

**Ubicación.** `checks/label_noise.py:167-174` (`accuracy < baseline + 0.05`).
**Reproducción** (`r02`, bloque C; 96 % benigno, 2 % de ruido inyectado, clases bien separadas):
`el modelo auxiliar no supera a la clase mayoritaria (0.979 contra 0.941)`. Con mayoritaria ≥ 0,95 la condición
exige exactitud > 1,0: el check no puede correr nunca. Es la proporción habitual del tráfico real.
**Corrección.** Usar exactitud balanceada (baseline 1/k) o un margen relativo (`(acc-base)/(1-base) ≥ 0,3`).
**Test.** El bloque C debe reportar ≈2 % de ruido.

### SCI-07 — los infinitos de CICFlowMeter se leen como nulos (Media, CONFIRMADO)

**Ubicación.** `io/readers.py:92` (`_CSV_NULL_VALUES = ["", "NaN", "nan", "Infinity", "-Infinity"]`).
**Reproducción** (`r01`, `r02` bloque I; CSV con `Infinity`, que es lo que escribe Java/CICFlowMeter):
```
low | La columna 'Flow Bytes/s' tiene 10 valores no finitos | {'null': 10.0, 'nan': 0.0, 'inf': 0.0, ...}
```
La regla "high si hay algún infinito" nunca se activa para estos CSV. `RESULTADOS.md:73` y `CHECKS.md:329`
afirman "2.867 infinitos … Verificado"; con este lector Vigía los reporta como nulos de severidad baja. No pude
verificarlo contra el archivo real (no se descargan datasets), pero el código no puede producir ese texto si el
CSV usa `Infinity`.
**Corrección.** No poner `Infinity`/`NaN` en `null_values`; leer esas columnas como texto y convertir con
`str.replace` + `cast(Float64)` (o un `schema_overrides` tras la inferencia), de modo que queden `inf`/`nan` reales.
**Test.** Un CSV con `Infinity` debe dar `inf > 0` y severidad `high`.

### COR-04 — `leak.session` corre sin la 5-tupla completa (Media, CONFIRMADO)

**Ubicación.** `checks/leakage.py:203` (`if len(tuple_cols) < 4`), contra CHECKS.md:160-162 ("Si falta alguna
columna, el check se salta"). El perfil `ctu-13` no declara `src_port_col` y `Sport` no se detecta.
**Reproducción** (`r02`, bloque G): sin puerto de origen, dos "sesiones" (pares host-servicio) → `critical`.
**Corrección.** Exigir las 5 columnas (`< 5`), agregar `src_port_col: Sport` al perfil CTU-13 y
`"sport"` a los candidatos de `src_port`. **Test.** Con 4 columnas, `CheckSkipped`.

### SCI-08 — `dup.near` no ve casi-duplicados de filas repetidas (Media, CONFIRMADO)

**Ubicación.** `checks/duplicates.py:298,311` (`is_duplicated()` excluye **todas** las copias).
**Reproducción** (`r02`, bloque E, 30 columnas, una fila casi idéntica):
```
con copia exacta -> sin hallazgo
sin copia exacta -> ['2 filas son casi duplicadas de otra (1 grupo(s))']
```
Agregar un duplicado exacto hace desaparecer el casi-duplicado: justo el caso de DoS repetitivo.
**Corrección.** Excluir solo las repeticiones (`is_first_distinct()` como representante).
**Test.** El bloque E debe reportar en ambos casos.

### COR-05 — un crash se reporta como un salto por diseño (Media, CONFIRMADO)

**Ubicación.** `core/engine.py:45-48`, `core/findings.py:111-128`.
**Defecto.** "error interno" va al mismo `skipped` que "falta la columna de split": en el JSON, la CLI y el panel
se ven iguales y, sin otros hallazgos, el semáforo es gris (no hay forma de que CI distinga "el programa falló").
**Corrección.** `report.errors` separado, `summary.n_errors`, salida de la CLI con código propio (3) y semáforo
que no pueda ser verde/gris si hubo errores.
**Test.** Un check que lanza `RuntimeError` → `n_errors == 1` y código 3.

### SEC-03 — Limitador de peticiones (Media, CONFIRMADO)

**Ubicación.** `api/security.py:59-93`.
**Reproducción** (`r06`, punto 1, sin clave): 35 POST con la misma cabecera → `{404: 30, 429: 5}`; con una
cabecera distinta por petición → `{404: 35}`. Con clave configurada la identidad es la única clave compartida:
cualquier cliente agota el cupo de todos. `_hits` nunca borra identidades viejas. Detrás de Caddy sin
`--forwarded-allow-ips`, `request.client.host` es la IP del proxy.
**Corrección.** Identidad = IP real (con `forwarded_allow_ips` configurado) cuando no hay clave, o por clave **y**
IP; podar entradas vacías; aplicar también a `/datasets`; tope global de trabajos (ya en PLAN).

### SEC-04 — bombas de descompresión Parquet en la validación (Media, CONFIRMADO)

**Ubicación.** `api/storage.py:117-131`.
**Reproducción** (`r07`): un Parquet de 50 M de ceros pesa **114 KiB** y ocupa **381 MiB** al leerlo (×3.419).
Dentro del límite de 500 MB cabe un archivo que se expande a cientos de GB; `read_parquet` corre completo, en el
hilo del event loop, antes de cualquier trabajo.
**Corrección.** Validar con `pl.read_parquet_schema` + metadatos (`num_rows`, tamaño descomprimido de los row
groups vía pyarrow) y rechazar por encima de un tope; leer con `n_rows` limitado; mover la validación a un hilo.

### SEC-05 — el límite de subida no corta el stream (Media, CONFIRMADO)

**Ubicación.** `api/storage.py:62-100` (docstring: "corta el stream apenas se supera el límite"); `docs/USO.md:189-192`.
**Reproducción** (`r06`, punto 8, `VIGIA_MAX_UPLOAD_MB=1`):
```
413 {"detail":"archivo de 62914560 bytes supera el limite de 1048576 bytes"} | enviado: 60 MiB de 60
```
Starlette/python-multipart ya escribió el cuerpo entero en un temporal (en `TMPDIR`, el volumen) antes de llamar
al endpoint; el bucle por trozos solo vuelve a copiarlo.
**Corrección.** Limitar en el proxy (`request_body { max_size 50MB }` en Caddy) y/o un middleware ASGI que corte
por `Content-Length` y por bytes recibidos; corregir docstring y USO.md.

### COR-06 — la API rechaza CSV en cp1252 (Media, CONFIRMADO)

**Ubicación.** `api/storage.py:124` (lee con `pl.read_csv` directo, sin el reintento de `io/readers._read_csv`).
**Reproducción** (`r06`, punto 2): `415 {"detail":"... ComputeError: invalid utf-8 sequence"}`. El día de ataques
web de CIC-IDS2017 no se puede subir por la API/panel, aunque RESULTADOS.md celebra que la CLI ya lo lee.
**Corrección.** Validar con la misma función que usa la auditoría (`read_dataset`, o su versión de esquema).

### COR-07 — el enlace al reporte HTML da 401 con clave (Media, CONFIRMADO)

**Ubicación.** `web/src/pages/Result.tsx:145` (`<a href={auditReportHtmlUrl(jobId)}>`).
**Reproducción** (`r06`, punto 7): con cabecera `200`, sin cabecera `401`. Un `<a>` no puede mandar `X-API-Key`.
CI solo prueba `/api/v1/checks` sin clave, así que no lo detecta.
**Corrección.** `fetch` con la cabecera → `Blob` → `URL.createObjectURL` y abrir eso; o un token de un solo uso
en la URL emitido por un endpoint autenticado.

### COR-08 — códigos de salida de la CLI (Media, CONFIRMADO)

**Ubicación.** `cli.py:175-214` atrapa solo `FileNotFoundError`, `ValueError`, `ProfileNotFound`.
**Defecto.** `ColumnNotFoundError`, `ComputeError` (Polars) y cualquier excepción inesperada salen con el
traceback de Typer y código **1**, que ARQUITECTURA.md:344 declara como "hay hallazgos que alcanzan `--fail-on`"
(contrato estable). Ejemplo: COR-02 (b).
**Corrección.** `except Exception` final → mensaje + `Exit(2)` (o 3 para errores internos, ver COR-05).

### PERF-01 — cuellos de botella (Media, CONFIRMADO)

**Medición** (`r07`, 1 M de filas × 48 columnas, 0,36 GiB en memoria, 28 núcleos):

| Check | Tiempo |
|---|---|
| `dup.near` | 76,8 s (muestra de 200.000; shingles y LSH en Python) |
| `shortcut.single_feature` | 13,9 s (un `group_by`+`join` por columna) |
| `labels.noise` | 5,5 s (se saltó por SCI-06) |
| `drift.feature` (fuera de la auditoría) | 8,9 s cada 5 columnas → ~70 s para 40 (`_histogram` y `ks_statistic` iteran en Python) |
| Total auditoría | 100 s, **pico RSS 2,50 GiB** (≈7× el DataFrame) |

El pico es coherente con los 5,4 GiB de USO.md para 1 M × 80 (≈9× un DataFrame de ~0,6 GiB).
**Corrección.** PSI con `search_sorted`/`cut` de Polars y KS con `np.searchsorted` (vectorizados);
`single_feature` en una sola pasada (`unpivot` + `group_by`), o sobre una muestra; `dup.near` bajando `MAX_ROWS`
o con firmas vectorizadas.

### CI-02 — huecos del CI (Media, CONFIRMADO)

**Ubicación.** `.github/workflows/ci.yml`. Sin `permissions: contents: read`; el front se compila solo dentro de
`docker build` (sin `npm run lint` ni build en CI); no se instala el wheel en un entorno limpio; no hay una pasada
sin `[ml]` (lo verifiqué a mano: funciona y los checks quedan saltados, ver §5); no hay `pip-audit`, que
`vigia.md:885` promete. **Corrección.** Agregar los cuatro pasos y fijar actions por SHA.

### CI-03 — `polars>=1.0` sin techo (Media, PROBABLE)

Los hashes de fila, la inferencia de esquema (de la que depende `promoted_int_overrides`), la semántica de
`n_unique` con nulos y el comportamiento de `is_in` con nulos son detalles de implementación de Polars, y varios
checks dependen de ellos (verificados en 1.44.2: NaN==NaN, null≠NaN, 0.0==-0.0 en hash, `group_by` y `unique`
coherentes). No lo pude probar contra una versión futura. **Corrección.** `polars>=1.20,<2`, y un test que
fije esas semánticas (el `r01` es casi ese test).

### DOC-01 — requisitos P0 dados por cumplidos (Media, CONFIRMADO)

README:15-17 dice "cubre los diez requisitos P0". Contra `vigia.md` §6.1:
- **R5**: "precisión de un modelo entrenado solo con ella" → es una regla por valor, en muestra, que ignora columnas
  continuas (SCI-05).
- **R6**: `leak.session` es "5-tupla + ventana de tiempo" en §8.4; no hay ventana (una 5-tupla reutilizada semanas
  después cuenta como la misma sesión).
- **R7**: "lista de registros sospechosos con puntaje de confianza": el reporte trae 10 ejemplos; `row_indices`
  se excluye del JSON a propósito y no hay otra salida (salvo `quarantine_noise`).
- **R8**: "el JSON valida contra un esquema": no existe esquema.
Además `labels.window` (§8.3, base del "valor de Vigía" según el propio diseño) no está implementado. **Corrección.**
Ajustar el README o completar; publicar `report.schema.json`.

### TEST-01 — calidad de las pruebas (Media, CONFIRMADO)

- `cli.py` 44 % de cobertura: `fix`, `poison`, `drift`, `serve` y el modo `--streaming` de la CLI sin cubrir.
- Ningún test de la Fase 1: ids con comodines, rotación de cabecera, límite de subida real, borrado de subidas
  huérfanas, enlace HTML con clave.
- `test_archivo_mas_grande_que_el_limite` pasa por `file.size`; no puede detectar SEC-05.
- Faltan propiedades: "fix + re-audit no tiene `dup.exact`" (habría encontrado COR-01), "eager == streaming"
  (COR-02), "compare no mejora sin defectos" (SCI-04), y casos con etiquetas nulas (COR-03) y fechas mezcladas (SCI-01/02).
- Los tests de la API usan `TestClient`, sin concurrencia real ni servidor.
No encontré tests triviales (`assert True`) ni mocks que reemplacen lo probado; los tres `is not None` del grep van
seguidos de aserciones de contenido.

### Bajas e info (resumen por hallazgo)

- **COR-09 Deep links 404.** `StaticFiles(html=True)` no tiene fallback de SPA: `/resultado/abc123 -> 404`,
  `/deriva -> 404` (`r06` punto 4). La API no queda sombreada (`/api/v1/checks -> 200`). Corrección: ruta
  catch-all que devuelva `index.html` para lo que no empiece con `/api` ni `/health`.
- **COR-10 Comando de "Corregir" inutilizable.** Usa `report.dataset.path`, que la API reemplaza por
  `dataset:<id>`; además el dataset ya se borró y faltan `--label-col/--split-col`. Corrección: mostrar el comando
  con un marcador `<archivo>` y las columnas usadas.
- **COR-11 Claves React duplicadas.** `validity.nan_inf` y `leak.host` emiten varios hallazgos con el mismo
  `check_id`; `key={f.check_id}` provoca advertencias y estado de `<details>` cruzado. Usar el índice + id.
- **COR-12 `validity.constant` con nulos.** `n_unique([7,7,7,None]) = 2` → no se reporta (`r02` F); el comentario
  de `validity.py:148` dice "ignorando nulos". `drop_constant` y streaming comparten el criterio. Usar
  `drop_nulls().n_unique() <= 1`.
- **COR-13 Patrón `uid`.** Sin borde de palabra, "ruido", "fluid", "guide" son "identificadores" (`r02` B): se
  reportan en `shortcut.identifier`, se borran con `drop_identifiers` y se excluyen de `labels.noise` y `poison.*`.
  Usar `\buid\b`.
- **COR-14 `category_col` ignorado.** `load` lee solo 8 roles; `unsw-nb15.yaml` declara `category_col: attack_cat`
  y su `known_issues` dice que filtra la etiqueta, pero sigue siendo característica (RESULTADOS.md:543 lo confirma).
  Validar claves de perfil contra un esquema y excluir `category_col` de `feature_cols`.
- **COR-15 Versión 0.1.0 por defecto.** USO.md enseña `run_audit(ctx, module="poison")`: ese reporte dice
  `vigia_version: 0.1.0`. Usar `vigia.__version__` como default.
- **COR-16 `--out` = entrada.** Se lee todo y se sobrescribe el original; rechazar si
  `out.resolve() == path.resolve()` y avisar si `<out>_cuarentena` ya existe.
- **SCI-09 `temporal_split` y nulos.** Las filas con tiempo nulo o no interpretable van a "test" (`r03` punto 5:
  las 40 filas → test; la re-auditoría da "sin hallazgo" por SCI-01). Marcarlas como sin split o rechazar.
- **SEC-06 Texto crudo de excepciones (PROBABLE).** `run_job` y `_validate_content` devuelven `type: mensaje`.
  En las pruebas no vi rutas del servidor (`r06` punto 3: "FileMetaData.version missing"), pero mensajes de Polars
  pueden incluir fragmentos de filas y rutas; el docstring "no filtrar detalles" no se cumple por construcción.
  Mensajes genéricos al cliente + id de correlación en el log.
- **SEC-07 Datos sensibles en reportes.** Los ejemplos son filas reales (IPs incluidas) y quedan en memoria sin
  caducidad; `vigia.md:882` promete IPs anonimizadas por defecto. Documentarlo o anonimizar en la API.
- **SEC-08 `VITE_API_KEY`.** `api.ts` sugiere fijarla en build time sin advertir que queda en el JS público; con
  `web/.env` presente, `COPY web/ ./` del Dockerfile la hornea en la imagen. La clave pegada en el panel vive solo
  en memoria (bien). Quitar la opción o advertirlo en el código y la doc.
- **SEC-09 Contenedor.** `node:22-slim`/`python:3.12-slim` sin digest; `curl` en runtime solo para el
  healthcheck (usar `python -c urllib...`); `/app/web/dist` es propiedad de `vigia` (escribible por el proceso:
  `chown` a root y solo lectura); uvicorn sin `--proxy-headers --forwarded-allow-ips` para Caddy; `.dockerignore`
  no excluye `.env`. El usuario no root es real (`USER vigia`) y el paquete se instala como root en site-packages
  (no escribible): bien.
- **SEC-10 `load_profile("../x")`.** `_PROFILES_DIR / f"{id}.yaml"` acepta `..` y lee cualquier YAML con
  `safe_load`. Solo CLI/SDK locales (la API no recibe perfiles): validar contra `available_profiles()`.
- **CI-04 sdist.** Sin lista de inclusión, hatchling empaqueta el árbol: en esta máquina el sdist pesa 28,6 MB
  con 3.752 archivos de `web/node_modules` (binarios de Windows) porque `vigia/` no tiene `.gitignore` propio. En
  el CI (checkout limpio) no pasaría, pero un `python -m build` local sí. Agregar
  `[tool.hatch.build.targets.sdist] include = ["src", "tests", "README.md", "LICENSE", "CHANGELOG.md"]`.
- **DOC-02 Detalles desactualizados.** CHECKS.md:27 dice "Hash xxhash" (es `hash_rows`); CHECKS.md:77-80 dice que
  `dup.near` ve dos flujos "que difieren en una sola columna", lo que con umbral 0,9 solo es cierto con ≥ 19
  columnas ((n-1)/(n+1) ≥ 0,9); el comentario del compose sobre el volumen (SEC-02); USO.md sobre el corte de la
  subida (SEC-05); DERIVA.md sobre concepto (SCI-03).
- **PERF-02 Validación en RAM.** `_validate_content` lee el archivo entero para contar filas, en el hilo del loop.
  Medido: 51 MB → `/health` máx. 0,11 s, mediana 3 ms (`r06` punto 6); escala lineal (≈1 s con 500 MB) y duplica el
  pico de memoria de la subida. Leer solo el esquema/metadatos y `to_thread`.
- **SEC-11 `!=` en la clave.** El timing remoto de una comparación de cadenas en CPython no es explotable en la
  práctica a través de red + TLS + Caddy; igual, `hmac.compare_digest` es una línea.
- **SEC-12 CORS.** La autenticación va en cabecera, no en cookies: `allow_credentials=True` no aporta nada y, con
  `VIGIA_CORS_ORIGINS=*`, Starlette refleja el origen. Ponerlo en `False` y rechazar `*` al arrancar.
- **CI-05 Metadatos.** "Development Status :: 3 - Alpha" con 1.0.0; la versión está en dos lugares.
- **DIS-01 Duplicación.** Nombres de split en `leakage.py:16-28` y `benchmark.py:94-95` (distintos: "prueba",
  "entrenamiento", "dev" no valen en el benchmark); checks reimplementados en streaming; extensiones en CLI y API;
  `AuditContext` reconstruido a mano en `cli.py`, `benchmark.py` (×2) — causa raíz de COR-01. Estado global de
  módulo (`_STORAGE_DIR` creado al importar, `_STORE`, `_rate_limiter`, `_REGISTRY`): `uvicorn --workers N`
  rompería la cola (cada worker con su `_STORE` y su directorio); USO.md lo insinúa ("una sola instancia") pero no
  lo dice explícitamente.
- **DIS-02 JSON sin versión de esquema.** ARQUITECTURA.md lo declara contrato estable, pero el JSON no trae
  `schema_version`; un consumidor en CI no puede detectar cambios. Agregar `"schema_version": "1"`.
- **TEST-02 venv.** `pip-audit` sobre `vigia/.venv` encuentra instalado `vigia 0.1.0` (metadatos de una instalación
  editable vieja con el nombre anterior): reinstalar con `pip install -e ".[dev,ml,parquet,api]"`.

---

## 4. Hipótesis descartadas

| Hipótesis | Por qué no es un problema |
|---|---|
| Timing attack sobre la clave (H1) | No explotable en la práctica por red; queda como SEC-11 (info) |
| Bloqueo grave del event loop (H5) | Existe pero es corto: 0,11 s máx. con 51 MB; queda como PERF-02 |
| Carrera entre dos trabajos sobre el mismo dataset (H6) | Lanzados juntos, ambos terminan (`r06` punto 5); uno lanzado después recibe un 404 determinista. Es la política "un dataset, un trabajo", no una carrera; conviene documentarla |
| Rutas del servidor en los errores (H7) | No observadas en las pruebas; queda como SEC-06 PROBABLE |
| Clave guardada en `localStorage` (H9) | Vive solo en memoria del módulo (`apiKeyOverride`) |
| `StaticFiles` sombrea la API (H16) | Se monta después de los routers: `/api/v1/*` y `/health` responden |
| XSS en `report/render.py` (H13) | Todo valor derivado del dataset pasa por `html.escape(quote=True)`; `color` sale de un dict fijo indexado por severidad validada; números con formato |
| XSS en el panel | Sin `dangerouslySetInnerHTML`; React escapa; el único `href` es una URL construida con `encodeURIComponent` |
| Colisiones de `hash_rows` a 16 M filas | P(alguna colisión) ≈ n²/2⁶⁵ ≈ 7·10⁻⁶: despreciable |
| NaN/null/-0.0 distintos entre eager, streaming y `drop_duplicates` | Verificado: hash, `group_by` y `unique` coinciden (NaN==NaN, null≠NaN, 0.0==-0.0) |
| `labels.noise` con probabilidades en muestra | Usa `cross_val_predict` (3 pliegues); el escalado va dentro del pipeline |
| Fuga en el benchmark (ajuste con test) | LightGBM se ajusta solo con train; solo el mapeo de categorías usa todo el dataset (códigos ordinales, sin etiqueta) |
| PSI, KS y JS numéricamente incorrectos | Coinciden con numpy/scipy a 6 decimales (`r04` bloque O); epsilon y bins repetidos se manejan bien |
| Caché `ctx.shared` dependiente del orden | La matriz se construye igual sea cual sea el detector que llega primero; mismo seed |
| `quarantine_noise` borra filas | Las aparta en `FixResult.quarantined` y la CLI las escribe; no hay borrado |
| Deserialización insegura / `subprocess` / YAML inseguro | Sin `pickle`, `eval`, `subprocess`; YAML con `safe_load` |
| `shortcut.single_feature` da falsos positivos por memorización | Con una columna de ruido de 25 % de únicos: 0,694 in-sample, lejos de 0,95 |
| Sin `[ml]` la CLI crashea | Instalé el wheel en un venv limpio: `audit` corre y lista `dup.near`/`labels.noise` como no ejecutados |
| El wheel no trae los perfiles | Trae los 6 YAML |
| Vulnerabilidades conocidas en dependencias | `pip-audit`: ninguna; `npm audit` (con y sin dev): 0 |

---

## 5. Áreas revisadas sin hallazgos

- **`dup.exact`, `dup.cross_split`, `dup.class_ratio`**: correctos con nulos en el split y alturas consistentes;
  la exclusión de columnas `__*` y de roles declarados se cumple en eager.
- **`leak.host`**: definición correcta (filas de test con IP vista en train), splits no reconocidos se informan.
- **`labels.taxonomy`, `labels.imbalance`**: umbral acotado al 10 %, nulos descartados.
- **`validity.impossible`**: centinela `-1` y comparación en Float64 (sin overflow en Int8).
- **Motor y registro**: aislamiento por check, `also_emits`, selección por prefijo dentro del módulo.
- **`render.py` y el panel**: escapado completo; semáforo con forma + palabra (accesible); gris siempre visible.
- **Envenenamiento**: normalización por detector en `combine.py`, exclusión de pesos cero del conteo de
  coincidencias, índices originales correctos tras muestrear. El simulador es optimista (flips aleatorios a otra
  clase), pero ENVENENAMIENTO.md ya lo dice y mide sobre tráfico real.
- **Empaquetado**: wheel de 132 KB, solo `vigia/` + perfiles; `vigia --help`, `vigia checks` y `vigia audit`
  funcionan desde el wheel.
- **Usuario no root en Docker**, `HEALTHCHECK` presente, `nfstream` fuera de la imagen.

---

## 6. Plan de remediación priorizado

**Antes de taggear v1.0.0** (≈3–4 días)

| Ítem | Esfuerzo |
|---|---|
| SEC-01 validar `dataset_id` y dejar de usar glob | 1 h |
| SCI-01 + SCI-02 + SCI-09 parser de tiempo estricto, detección de ambigüedad, `time_format` | 4–6 h |
| COR-01 `ctx.replace()` único + test de propiedad fix→re-audit | 2 h |
| SCI-04 evaluación sobre test fijo en `compare()` | 3 h |
| SCI-03 renombrar o implementar concepto con etiqueta; corregir DERIVA.md | 2 h (renombrar) / 1 día (implementar) |
| SCI-05 discretizar columnas continuas en `single_feature` | 3 h |
| COR-03, SCI-06, SCI-08, COR-04, COR-12, COR-13 (arreglos de una línea + test cada uno) | 4 h |
| SCI-07 conservar `inf`/`nan` del CSV y corregir CHECKS/RESULTADOS | 2 h |
| COR-02 detección y `strip` en streaming + `skipped` honesto | 2 h |
| COR-05 + COR-08 errores separados y códigos de salida | 2 h |
| CI-01 tests, chequeo de versión, SHA, `permissions` en release | 1 h |
| DOC-01/DOC-02 ajustar README y docs | 2 h |

**Antes de desplegar** (≈2 días, además de lo de PLAN.md)

| Ítem | Esfuerzo |
|---|---|
| SEC-02 TTL de subidas, cuota de disco, limpieza al arrancar, rate limit en `/datasets` | 4 h |
| SEC-05 límite en Caddy + middleware ASGI | 1 h |
| SEC-04 validar Parquet por metadatos, con tope | 2 h |
| SEC-03 identidad por IP real/clave, poda de `_hits`, `forwarded_allow_ips` | 2 h |
| COR-07 descarga del HTML con cabecera | 1 h |
| COR-06 validar con `read_dataset` | 30 min |
| COR-09 fallback de SPA | 30 min |
| SEC-06, SEC-09, SEC-12 endurecimiento | 2 h |
| Tope de trabajos y caducidad de reportes (PLAN.md) | 3 h |

**Después**

| Ítem | Esfuerzo |
|---|---|
| PERF-01 PSI/KS vectorizados, `single_feature` en una pasada | 1 día |
| CI-02 lint del front, wheel limpio, pasada sin `[ml]`, `pip-audit` | 2 h |
| CI-03 techo de Polars + test de semántica | 1 h |
| TEST-01 tests de CLI y de API con servidor real | 1–2 días |
| DOC-01 esquema JSON (R8), salida de filas sospechosas (R7), ventana en `leak.session` (R6) | 2 días |
| COR-10, COR-11, COR-14, COR-15, COR-16, SEC-07, SEC-08, SEC-10, CI-04, CI-05, DIS-01, DIS-02 | 1 día en total |

---

## 7. Anexo

### 7.1 Línea base (04/10/2026, Windows 11, Python 3.13.5, Polars 1.44.2)

```
pytest -q --cov=src      268 passed in 64.84s; cobertura total 89,92 % (mínimo 85 %)
  peor cubiertos: cli.py 44 %, io/pcap.py 67 %, api/storage.py 86 %, api/jobs.py 88 %
ruff check src tests     All checks passed!
mypy src                 Success: no issues found in 43 source files
pip-audit (vigia/.venv)  No known vulnerabilities found  (omitido: vigia 0.1.0, ver TEST-02)
npm audit (web/)         found 0 vulnerabilities (con y sin dependencias de desarrollo)
python -m build          vigia_nids-1.0.0-py3-none-any.whl 132 KB; vigia_nids-1.0.0.tar.gz 28,6 MB (CI-04)
```

Versiones de la API probada: FastAPI 0.141.1, Starlette 1.7.0, python-multipart 0.0.32, uvicorn 0.53.0.

### 7.2 Scripts de reproducción

Se escribieron fuera del repo, en el directorio temporal de la sesión
(`%TEMP%\claude\...\scratchpad\repro\`). Se corren con el venv del proyecto
(`vigia\.venv\Scripts\python.exe <script>`); `r06_api.py` necesita `httpx` (venv cliente aparte) y la variable
`VIGIA_PY` apuntando al Python del proyecto, y levanta/apaga su propio uvicorn en 127.0.0.1.

| Script | Qué reproduce |
|---|---|
| `r01_polars_semantica.py` | Semántica de `hash_rows`, `group_by`, `unique`, `n_unique`, `is_in` y `null_values` (SCI-07, COR-12, CI-03) |
| `r02_checks.py` | COR-03, SCI-05, SCI-06, SCI-08, COR-12, COR-04, SCI-07, COR-13 |
| `r03_temporal.py` | SCI-01, SCI-02, SCI-09 |
| `r04_fix_stream_drift.py` | COR-01, SCI-04, COR-02, SCI-03 y contraste de PSI/KS/JS con numpy/scipy |
| `r05_glob.py` | SEC-01: el patrón de `dataset_path` evaluado localmente (sin servidor) |
| `r06_api.py` | SEC-03, COR-06, SEC-06, COR-09, H6, PERF-02, COR-07, SEC-05 |
| `r07_perf.py` | PERF-01 y la relación de compresión de SEC-04 |

Núcleo de las reproducciones principales, por si el directorio temporal ya no existe:

```python
# SCI-01: fuga real que desaparece
train = [f"2017-07-{d:02d} 10:00:00" for d in range(10, 20)] * 50
test = [f"2017-07-{d:02d} 11:00:00" for d in range(21, 30)] * 45 + [f"{d}/7/2017 9:00" for d in range(1, 9)] * 5
df = pl.DataFrame({"Timestamp": train + test, "split": ["train"]*len(train) + ["test"]*len(test), "f": range(len(train)+len(test))})
run_audit(AuditContext(df=df, split_col="split", time_col="Timestamp"), checks="leak.temporal").findings  # -> []

# SCI-03: concepto invertido, semáforo verde
ref = pl.DataFrame({"x1": x1, "x2": x2, "Label": np.where(x1 + x2 > 0, "ATTACK", "BENIGN")})
cur = pl.DataFrame({"x1": x1b, "x2": x2b, "Label": np.where(x1b + x2b > 0, "BENIGN", "ATTACK")})
ctx = AuditContext(df=cur, label_col="Label"); ctx.reference = ref
run_audit(ctx, module="drift").traffic_light()  # -> 'verde'

# SCI-04: F1 inflado
compare(AuditContext(df=df, label_col="Label", split_col="split"), ["quarantine_noise"]).summary()
# -> 'F1 macro: 0.7555 -> 0.9082 (+0.1527)'  (n_test 1810 -> 1516)

# COR-01
vigia audit k.csv --time-col Timestamp                          # 90,00 % duplicados
vigia fix k.csv --apply drop_duplicates --time-col Timestamp --out k_fix.csv   # quita 23 de 270
vigia audit k_fix.csv --time-col Timestamp                      # 89,17 % duplicados
```

---

## 8. Estado de la remediación

Rama `auditoria-1.0` (37 commits sobre `main`: `git log --oneline main..auditoria-1.0`).
Alcance: el bloque "antes de taggear v1.0.0" de la sección 6, más SEC-11. No se
tocó nada de "antes de desplegar" ni de "después", salvo la parte de DOC-02 que
afirmaba cosas falsas sobre la API.

Verificación final (05/10/2026): `pytest -q --cov=src` → **352 passed**, cobertura
**92,15 %** (línea base: 268 passed, 89,92 %); `ruff check`, `ruff format --check`
y `mypy src` limpios; `npm run build` y `npm run lint` (en `vigia/web`) correctos.
La suite tarda entre 78 y 148 s según la carga de la máquina (los tests
anteriores a la rama de control limpio y de formatos suman ~35 s; los de esta rama
aportan del orden de 10 s, según `--durations`).

Las reproducciones del anexo 7.2 se volvieron a correr (`r09_despues.py`, fuera
del repo): SCI-01 y SCI-02 se saltan con motivo en vez de dar "sin hallazgo" o un
crítico falso; SCI-03 da `drift.concept` crítico y semáforo rojo; SCI-04 pasa de
+0,1527 a +0,0045; COR-01 deja de tener `dup.exact` tras `fix`; SCI-05, SCI-06,
SCI-07, COR-03 y COR-05 dan el resultado correcto; SEC-01 responde 422 a los cinco
ids y el dataset ajeno sigue existiendo.

| ID | Estado | Commit | Test que lo cubre |
|---|---|---|---|
| SEC-01 | corregido | `417ed0b` | `test_api.py::test_dataset_id_con_comodines_se_rechaza_y_no_toca_datasets_ajenos`, `test_storage_no_interpreta_el_id_como_patron`, `test_job_id_con_forma_invalida_da_422` |
| SEC-11 | corregido | `3e08af2` | sin test nuevo (la diferencia es de tiempo); `test_api_key_incorrecta_da_401` sigue pasando |
| COR-01 | corregido | `8fa78ae`, `069ebbd` (`--profile`) | `test_fixes.py::test_fix_drop_duplicates_y_reauditar_no_deja_dup_exact`, `test_with_df_conserva_los_roles_y_no_arrastra_las_caches`, `test_fix_acepta_perfil`; `test_benchmark.py::test_compare_respeta_los_roles_declarados` |
| SCI-01 | corregido | `85165af` | `test_leakage.py::test_filas_con_otro_formato_no_se_descartan_en_silencio`, `test_split_sin_tiempo_no_se_confunde_con_split_no_reconocido` |
| SCI-02 | corregido | `85165af`, `9cc3668` (`time_format`) | `test_leakage.py::test_fechas_us_con_dias_mayores_a_12_se_interpretan_bien`, `test_fechas_ambiguas_d_m_contra_m_d_se_saltan_y_piden_el_formato`, `test_cli_audit_acepta_time_format`, `test_el_perfil_puede_fijar_time_format`; `test_api.py::test_la_auditoria_acepta_time_format` |
| SCI-09 | corregido | `928b878` | `test_fixes.py::test_temporal_split_no_manda_a_prueba_las_filas_sin_tiempo`, `test_temporal_split_con_tiempo_ambiguo_no_aplica` |
| SCI-04 | corregido | `fe41d0b` | `test_benchmark.py::test_compare_con_cuarentena_no_infla_el_f1_sobre_datos_sin_ruido`, `test_compare_avisa_cuando_cambia_el_conjunto_de_prueba` |
| SCI-03 | corregido (opción b, implementar) | `9833c45`, `6bf2ee6` (docs) | `test_drift.py::test_concepto_invertido_no_da_verde`, `test_concepto_estable_no_reporta`, `test_concepto_sin_etiqueta_en_el_lote_se_salta_y_lo_dice` |
| SCI-05 | corregido | `a406673` | `test_shortcuts.py::test_columna_continua_que_separa_por_umbral_se_reporta`, `test_ruido_continuo_puro_no_se_reporta` |
| COR-03 | corregido | `37431ff` | `test_labels.py::test_conflicto_con_etiquetas_nulas_no_crashea` |
| SCI-06 | corregido | `19791d9` | `test_label_noise.py::test_corre_con_clase_mayoritaria_del_96_por_ciento` |
| SCI-08 | corregido | `f3b1ccd` | `test_duplicates.py::test_casi_duplicado_de_una_fila_repetida_se_ve` |
| COR-04 | corregido | `653e35a` | `test_leakage.py::test_sesion_se_salta_con_cuatro_de_cinco_columnas`, `test_sport_se_detecta_como_puerto_de_origen`, `test_el_perfil_ctu13_declara_el_puerto_de_origen` |
| COR-12 | corregido | `e771186` | `test_validity.py::test_constant_ignora_los_nulos`; `test_fixes.py::test_drop_constant_ignora_los_nulos`; `test_streaming.py::test_columna_constante_con_nulos_en_streaming` |
| COR-13 | corregido | `ba912b0` | `test_shortcuts.py::test_palabras_que_solo_contienen_uid_o_flow_id_no_son_identificadores`, `test_los_identificadores_reales_se_siguen_reconociendo` |
| COR-15 | corregido | `43439f2` | `test_engine_y_cli.py::test_la_version_por_defecto_es_la_del_paquete` |
| COR-16 | corregido | `f5ca740` | `test_engine_y_cli.py::test_fix_se_niega_a_sobrescribir_la_entrada` |
| SCI-07 | corregido; texto de los documentos: decisión resuelta (marcar pendiente) | `8bc595a`, `9f453e3` (docs) | `test_readers.py::test_csv_conserva_infinity_y_nan_como_valores_reales`, `test_validity_nan_inf_ve_los_infinitos_del_csv`, `test_streaming_ve_los_mismos_infinitos`, `test_infinitos_tambien_con_el_respaldo_cp1252`, `test_una_columna_de_texto_no_se_convierte_a_numero` |
| COR-02 | corregido | `58a9333` | `test_streaming.py::test_streaming_detecta_etiqueta_y_split_por_nombre`, `test_streaming_acepta_el_nombre_sin_el_espacio_de_cicflowmeter`, `test_streaming_dice_que_dup_cross_split_no_corrio`, `test_streaming_y_modo_normal_dan_lo_mismo_sobre_un_csv_de_cicflowmeter` |
| COR-05 | corregido | `f5b3540`, `987e6b7` (HTML), `ed32e76` (panel), `25a3ec3` (docs) | `test_engine_y_cli.py::test_un_check_roto_no_tumba_la_auditoria`, `test_un_check_que_falla_no_deja_el_semaforo_verde_ni_gris`, `test_el_html_muestra_los_errores_aparte_y_no_dice_que_todo_corrio`; el panel solo tiene `tsc` y lint (no hay tests de front) |
| COR-08 | corregido | `4be02a2` | `test_engine_y_cli.py::test_cli_un_check_que_falla_sale_con_3_y_lo_dice`, `test_cli_un_error_inesperado_sale_con_3_y_sin_traceback`, `test_cli_una_columna_inexistente_es_un_error_de_uso`, `test_cli_drift_con_un_check_roto_no_dice_que_no_hace_falta_reentrenar`, `test_cli_con_hallazgos_que_alcanzan_fail_on_gana_el_1` |
| DIS-02 | corregido (`schema_version`, decisión resuelta: sí) | `f5b3540` | `test_engine_y_cli.py::test_el_json_lleva_errors_n_errors_y_schema_version` |
| DIS-01 | parcial | `8fa78ae` | `AuditContext.with_df` unifica la reconstrucción del contexto (causa de COR-01); siguen duplicadas las listas de splits entre `leakage.py` y `benchmark.py` y la lógica eager/streaming |
| CI-01 | corregido | `e978783` (versión única), `e552e6f` (`release.yml`) | `test_engine_y_cli.py::test_la_version_sale_de_los_metadatos_y_coincide_con_pyproject`, `test_sin_el_paquete_instalado_la_version_tiene_un_respaldo`; `release.yml` **no se pudo ejecutar** (solo corre con un tag): se validó el YAML, los permisos, que las 7 actions llevan SHA verificado con `gh api`, y se simuló el paso de versión (`v1.0.0` pasa, `v1.0.1` falla) |
| CI-04 | corregido | `479c207` | sin test; sdist construido en un directorio temporal: 94 entradas, 228 KB (antes 28,6 MB), sin `web/` ni `node_modules` |
| CI-05 | corregido (el nivel lo elegí yo) | `479c207` | wheel: `Classifier: Development Status :: 4 - Beta` |
| DOC-01 | corregido | `73c4139` | documentación |
| DOC-02 | corregido | `6bc8141`, `be0631f`, `b578b07`, `6bf2ee6` | documentación |
| TEST-02 | resuelto fuera del repo | — | `pip install -e ".[dev,ml,parquet,api]"`; `importlib.metadata.version("vigia-nids")` da `1.0.0` |

**Decisiones ⚠ (las cuatro respondidas por Joshua antes de empezar):** `time_format`
público (sí), `drift.concept` real (implementar), cifra de 2.867 infinitos (marcar
pendiente de re-medir) y `errors` + `schema_version` en el JSON (sí, ahora).

**Decisión mía que conviene revisar:** el classifier es `4 - Beta`, no
`5 - Production/Stable`; y el semáforo con un check roto es **rojo**, no
amarillo. Las dos son una línea de cambiar.

**Pendiente de medir sobre datos reales (no se descargan en esta tanda):** los
2.867 infinitos de CIC-IDS2017; el control negativo de la tabla de deriva de
`DERIVA.md` con el nuevo `drift.concept` (el lunes tiene una sola clase: se
saltaría y el control daría gris); y `drift.concept` en general.

### Problemas nuevos, encontrados y sin arreglar

1. **`vigia fix` sale con código 1 cuando ninguna corrección se pudo aplicar**
   (`cli.py`, "Ninguna corrección se pudo aplicar"), y el 1 significa "hay
   hallazgos que alcanzan `--fail-on`". Debería ser otro código (2 o 3).
2. **`ci.yml` sigue sin `permissions`, con las actions por tag y sin lint del
   front** (CI-02, bloque "después"). Solo se endureció `release.yml`.
3. **`Report.errors` guarda `str(exc)` tal cual**, y el mensaje de una excepción de
   Polars puede incluir fragmentos de filas o rutas; viaja por la API y el panel
   (misma raíz que SEC-06).
4. **`drift.concept` es nuevo y no está medido sobre tráfico real**; sus umbrales
   (caída de 0,10 y 0,25) son una elección razonable, no una calibración.
5. **La suite supera los ~90 s en esta máquina** (78 a 148 s según la carga). El
   grueso son tests anteriores a la rama; no se tocaron.
6. **`shortcut.single_feature` sobre columnas continuas** se midió a 1 M de filas
   × 45 columnas (3,5 s, sin regresión), pero solo en un dataset sintético; sobre
   datos reales con muchas columnas de alta cardinalidad no se midió.
7. **`validity.nan_inf` en `--streaming` no agrupa por perfil** (reporta cada
   columna por separado), a diferencia del modo normal: queda documentado en
   `USO.md`, no unificado.
8. **No pude ver el panel en un navegador**: la verificación del front es `tsc`
   (en `npm run build`) y `oxlint`.
9. **Los commits anteriores al cambio de modelo** llevan `Co-Authored-By: Claude
   Opus 5.5` y los posteriores `Claude Sonnet 5.5`, según el recordatorio de
   atribución de cada momento.


---

## 9. Estado de la remediación (despliegue)

Rama `despliegue-1.0`, creada desde `auditoria-1.0` (que todavía no está mergeada en
`main`): 19 commits más (`git log --oneline auditoria-1.0..despliegue-1.0`).
Alcance: el bloque "antes de desplegar" de la sección 6, el problema nuevo 1 de la
sección 8 y la parte de CI-02 que cubre lo que se despliega. Nada de "después".

Verificación final (05/10/2026): `pytest -q --cov=src` → **411 passed**, cobertura
**93 %** (la rama anterior: 352 passed, 92,15 %); `ruff check`, `ruff format --check`
y `mypy src` limpios; `npm run build` y `npm run lint` correctos; `docker build`
correcto. La suite sin cobertura tarda entre 66 y 80 s en esta máquina (la línea
base de esta tanda dio 54 s, con la máquina menos cargada); los tests nuevos suman
unos 10 s, casi todos de `test_api_trabajos.py`.

**Compose de producción probado en local** (`VIGIA_DOMAIN=localhost`, `curl -k`, imagen
construida desde esta rama): 401 sin clave y con clave mala, 200 con clave, 413 con
2,8 MB y límite de 1 MiB (con `Content-Length`, chunked por Caddy y chunked directo a
la API), 201 con un archivo chico, HSTS, `X-Content-Type-Options`, `Referrer-Policy`,
`X-Frame-Options` y CSP presentes, `/resultado/abc` con 200 `text/html`,
`/api/v1/no-existe` con 404 JSON, el puerto 8000 sin respuesta en el host, la API
`healthy` con el sistema de archivos de solo lectura, `touch` en `/app/web/dist` y
`/app/src` rechazado, y la imagen con `VIGIA_ENV=production` y sin clave no arranca.
Los logs de la API muestran la IP real del cliente (`172.28.0.1`), no la de Caddy.

**Panel recorrido en un navegador real** (Chrome headless manejado por el protocolo
de depuración, contra ese mismo compose, con la clave configurada y la CSP de Caddy):
subir y auditar un CSV, ver el resultado (semáforo y 5 hallazgos), abrir el reporte HTML
(pestaña `blob:` con el título del reporte, sin la clave en la URL), el comando de
"Corregir" (`vigia fix <archivo> --apply drop_duplicates --label-col "label" --out
<archivo>_corregido.parquet`), recargar `/resultado/<id>` (devuelve el panel, no un
404) y deriva con dos archivos hasta el resultado. Sin errores de JavaScript en consola.
No es una suite de tests del front (el panel sigue sin ellos): el script quedó fuera
del repo, en el directorio temporal de la sesión.

| ID | Estado | Commit | Test que lo cubre |
|---|---|---|---|
| Configuración centralizada | corregido | `265daab` | `test_api_config.py` (valores por defecto, inválidos, arranque que falla) |
| SEC-05 | corregido | `93e4342` | `test_api_limites.py::test_content_length_declarado_por_encima_del_limite_da_413`, `test_cuerpo_chunked_sin_content_length_tambien_da_413`, `test_el_stream_se_corta_apenas_se_supera_el_limite` |
| SEC-02 | corregido | `664597a` | `test_api_disco.py` (TTL, reclamada no caduca, cuota con y sin `Content-Length`, limitador en la subida, directorio viejo / ajeno vivo / propio) |
| Tope de trabajos y caducidad de reportes | corregido (decisión: encolar + 503) | `118a81f` | `test_api_trabajos.py` (tope con máximo observado 1, cola llena → 503 + `Retry-After`, dataset en cola no caduca, reporte caducado → 410, tope en memoria) |
| SEC-04, PERF-02 | corregido | `d0e0567` | `test_api_validacion.py::test_un_parquet_que_se_expande_se_rechaza_sin_descomprimirlo`, `test_un_csv_se_valida_con_una_muestra_y_las_filas_siguen_exactas`, `test_validar_no_bloquea_el_event_loop` |
| COR-06 | corregido | `d0e0567` | `test_api_validacion.py::test_un_csv_en_cp1252_sube_como_en_la_cli` |
| SEC-03 | corregido | `573d8cc`, `efc13aa` | `test_api_limitador.py` (rotar la cabecera no evade, con clave, poda de 10.000 identidades, tope de identidades) |
| SEC-06, problema nuevo 3 | corregido | `dc467ac` | `test_api_errores.py` (trabajo, subida ilegible y check roto: no filtran, y el log tiene el mismo id) |
| COR-09 | corregido | `fc43c19` | `test_api_spa.py` |
| SEC-12 | corregido | `1766750` | `test_api_config.py::test_cors_con_comodin_hace_fallar_el_arranque`, `test_cors_no_permite_credenciales` |
| SEC-09 | corregido (el arranque en producción: `VIGIA_ENV=production`, decisión de Joshua) | `1766750`, `c861b5d`, `8539051` | `test_api_config.py::test_en_produccion_el_arranque_falla_sin_clave_de_api`; el Dockerfile y el compose, probados a mano (arriba) |
| COR-07, COR-10, COR-11, SEC-08 | corregido | `b0c16c2` | sin tests de front: `tsc`, `oxlint`, el bundle sin `VITE_API_KEY` y el recorrido en navegador (arriba) |
| Problema nuevo 1 (sección 8) | corregido | `f0d50f6` | `test_engine_y_cli.py::test_fix_sin_ninguna_correccion_aplicable_es_un_error_de_uso` |
| CI-02 | parcial (sin la pasada sin `[ml]` ni `pip-audit`, bloque "después") | `5390940` | el YAML se parseó y los comandos nuevos del job de Docker se corrieron a mano; el workflow no se pudo ejecutar fuera de GitHub |
| Documentación | corregido | `bc3bde7`, `5c45175`, `cb93b0c`, `a10df24` | documentación |

**Decisiones ⚠ (las cuatro respondidas por Joshua):** límite de subida por defecto de 200 MB,
encolar con una cola chica y 503 con `Retry-After` cuando se llena, `n_rows` exacto en
`DatasetUploadResponse` (se cuentan las filas sin cargar el archivo) y `VIGIA_ENV=production`
como mecanismo para que producción no arranque abierta.

### Problemas nuevos, encontrados y sin arreglar

1. **Recargar el panel pierde la clave de API** (vive solo en memoria, a propósito, por
   SEC-08). Un enlace profundo recargado muestra el panel pero el primer pedido da 401, y
   después de pegar la clave la pantalla no reintenta sola: hay que volver a entrar.
2. **Si el navegador bloquea la ventana emergente**, "Ver el reporte HTML" navega la
   misma pestaña al Blob y se pierde la clave en memoria. Con un clic real la pestaña nueva
   se abrió bien.
3. **El reporte HTML abierto desde un Blob comparte el origen del panel.** Hoy la plantilla
   no tiene scripts (no hay `<script>` en `report/`), pero si algún día los tuviera, o si
   un valor del dataset llegara sin escapar, correría con acceso a lo que tiene el panel.
4. **SEC-07 sigue abierto**: los reportes de la API exponen filas e IPs reales del
   dataset, y cualquiera con la clave y el id de un trabajo (32 hex al azar) lo puede
   leer. Con una sola clave compartida no hay forma de atar un trabajo a un cliente.
5. **Sin tope de tiempo por trabajo.** Un trabajo colgado ocupa su lugar en el tope (1
   por defecto) hasta que se reinicie el contenedor, y los que esperan en la cola no avanzan.
6. **El limitador corre después de leer el cuerpo**: FastAPI parsea el formulario antes
   de resolver las dependencias, así que una subida rechazada con 429 ya gastó ancho de
   banda y disco temporal (acotados por el límite de subida, no evitados).
7. **Caddy y la API comparten el mismo límite** (`request_body max_size` = `VIGIA_MAX_UPLOAD_MB`
   MiB), pero Caddy mide el cuerpo completo: un archivo de tamaño exactamente igual al límite
   lo rechaza Caddy por el encuadre del multipart. Es un margen de unos cientos de bytes.
8. **La limpieza al arrancar con candados se probó en Windows** (`msvcrt`); la rama de
   Linux (`fcntl.flock`) es la que corre en el contenedor: arrancó y atendió subidas, pero
   los tests de directorios viejos / ajenos / propios solo los vi pasar acá. El job `test` de
   CI sobre `ubuntu-latest` los va a correr por primera vez.
9. **`ci.yml` y `release.yml` no se pudieron ejecutar.** El del CI porque solo corre en
   GitHub; el de publicación, porque solo corre con un tag.
10. **Los problemas nuevos 2 (el resto de CI-02), 4, 5, 6, 7 y 9 de la sección 8** siguen
    como estaban.
