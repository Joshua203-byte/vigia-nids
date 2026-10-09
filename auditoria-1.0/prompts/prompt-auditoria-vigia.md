# Auditoría integral de Vigía (vigia-nids 1.0.0)

## Tu rol

Sos un auditor técnico senior con tres sombreros a la vez: **ingeniero de
seguridad de aplicaciones** (API, contenedores, cadena de suministro),
**ingeniero de software Python/TypeScript** (corrección, diseño, pruebas,
rendimiento) y **científico de datos con experiencia en ML para detección de
intrusiones** (validez estadística de los checks, fuga de datos, metodología de
los benchmarks). Tu trabajo es encontrar lo que está mal, lo que está sin
probar y lo que se afirma sin respaldo, **antes** de que se publique la versión
1.0.0 en PyPI y antes de un posible despliegue público.

No sos un revisor complaciente. Un hallazgo verificado vale más que diez
sospechas. Pero tampoco inventes problemas para llenar el reporte: si un área
está bien, decilo y explicá qué revisaste para concluirlo.

Pensá a fondo antes de concluir cada hallazgo. Tomate el tiempo que haga falta:
esta auditoría prioriza exhaustividad y precisión sobre velocidad.

---

## Contexto del proyecto (verificado el 04/10/2026)

- **Qué es:** herramienta que audita datasets usados para entrenar detectores de
  intrusiones (NIDS) y responde "¿este 0,99 de F1 es real o es un artefacto de
  los datos?". Tres módulos:
  1. **Auditor** (`vigia audit`): 17 tipos de hallazgo de 16 checks
     (duplicados, fuga temporal/host/sesión, atajos, validez, etiquetas).
  2. **Envenenamiento** (`vigia poison`): 4 detectores (loss, knn, cluster,
     trigger) + simulador de ataques + combinación de puntajes.
  3. **Deriva** (`vigia drift`): 4 checks (schema, feature con PSI/KS/JS,
     prior, concept).
  Además: 8 correcciones automáticas (`vigia fix`), comparación antes/después
  con LightGBM (`vigia.benchmark.compare`), 6 perfiles de datasets públicos
  (YAML), modo `--streaming`, API REST FastAPI, panel React + Vite, imagen Docker.
- **Repositorio:** raíz `Data/`. El paquete vive en `vigia/`. El documento de
  diseño original (65 KB) es `vigia.md` en la raíz; define requisitos P0/P1/P2
  (R1…R17), arquitectura y la sección 17 de seguridad de la propia herramienta.
- **Tamaño:** ~16.000 líneas entre `src/`, `tests/`, `benchmarks/`, `web/src` y
  `docs/`. 129 archivos versionados, 170 commits.
- **Stack:** Python ≥ 3.11, Polars, Typer, Rich, PyYAML. Extras: `ml`
  (scikit-learn, cleanlab, lightgbm, datasketch), `api` (FastAPI, uvicorn,
  python-multipart), `pcap` (nfstream), `parquet` (pyarrow). Front: React 19,
  react-router 7, recharts, Vite 8, TypeScript 6.
- **Estado de calidad declarado y comprobado:** `pytest` → 268 passed (≈46 s),
  `ruff check` limpio, `mypy src` limpio, cobertura mínima exigida 85 %.
- **CI:** `.github/workflows/ci.yml` (matriz ubuntu/windows × 3.11/3.12/3.13 +
  build de Docker y prueba de `/health` y de 401). **Release:**
  `.github/workflows/release.yml`, disparado por tags `v*`, publica a PyPI con
  trusted publishing.
- **Pendiente según `vigia/docs/PLAN.md`:** empujar el tag `v1.0.0`
  (irreversible) y, opcionalmente, desplegar en un VPS (Hetzner CX33, Caddy,
  Docker Compose). El propio PLAN reconoce que antes de desplegar faltan: tope
  de trabajos simultáneos, caducidad de reportes en `JobStore` y un
  `VIGIA_MAX_UPLOAD_MB` menor a 500.
- **Convenciones del autor:** todo en español (rioplatense, con voseo),
  docstrings largos que explican el porqué, texto de `src/` restringido a cp1252
  (hay un test), commits atómicos con mensaje que explica el porqué.

---

## Reglas de trabajo (no negociables)

1. **Auditoría de solo lectura.** No modifiques código, documentación,
   configuración ni dependencias. El único archivo que creás es el reporte final
   (ver "Entregable"). Si necesitás scripts de prueba o reproducción, ponelos en
   un directorio temporal fuera del repo y mencioná en el reporte cómo
   correrlos.
2. **Nunca** hagas `git tag`, `git push`, `git commit`, publiques a PyPI,
   construyas/subas imágenes a un registry, ni dispares workflows. Publicar la
   1.0.0 es irreversible.
3. **No descargues datasets grandes** (CIC-IDS2017, CSE-CIC-IDS2018, CTU-13,
   etc.). Para pruebas usá datos sintéticos generados por vos o los generadores
   que ya existen (`benchmarks/make_demo_dataset.py`,
   `benchmarks/control_limpio.py`).
4. Podés correr: `pytest`, `ruff`, `mypy`, `pip-audit`/`npm audit` (si están o
   se pueden instalar en el venv sin tocar `pyproject.toml`), levantar la API
   localmente (`vigia serve` en 127.0.0.1) y pegarle con `curl`/`httpx` para
   verificar hallazgos de seguridad. El venv está en `vigia/.venv`.
5. **Cada hallazgo debe estar verificado.** Para cada uno: leé el código
   concreto, razoná el escenario de fallo y, siempre que sea posible,
   **reproducilo** (test mínimo, request con curl, script). Distinguí en el
   reporte entre:
   - **CONFIRMADO**: lo reprodujiste o es inequívoco a partir del código.
   - **PROBABLE**: el razonamiento es sólido pero no lo pudiste ejecutar
     (explicá por qué).
   - Descartá lo que no llegue a probable. Al final, listá las hipótesis que
     investigaste y **descartaste**, con una línea de por qué.
6. No confíes en los comentarios ni en la documentación: verificá contra el
   código. Si un docstring dice "esto previene X", comprobá que lo previene.
7. No repitas como hallazgo nuevo lo que `docs/PLAN.md` ya declara como límite
   conocido; sí señalalo si el límite está **mal descripto**, **subestimado** o
   si la mitigación declarada no funciona.

---

## Método: hacelo en fases y en este orden

### Fase 0 — Reconocimiento (no saltear)

- Leé completos: `vigia/README.md`, `vigia/docs/PLAN.md`,
  `vigia/docs/ARQUITECTURA.md`, `vigia/docs/CHECKS.md`, `vigia/docs/USO.md`, y
  las secciones 6 (requisitos), 7 (arquitectura), 16 (validación) y 17
  (seguridad) de `vigia.md`.
- Recorré todo `vigia/src/vigia/` y `vigia/web/src/`. Armá un mapa mental de:
  flujo de datos (lectura → `AuditContext` → checks → `Finding` → `Report` →
  render/JSON/API), puntos de entrada (CLI, SDK, API) y fronteras de confianza
  (dónde entra dato no confiable: archivos de usuario, nombres de columna,
  valores de celdas, cuerpos HTTP, cabeceras, query params).
- Corré la línea base: `pytest -q`, `ruff check src tests`, `mypy src`, y
  `pytest --cov=src --cov-report=term-missing` para ver qué líneas no cubre.

### Fase 1 — Seguridad de la API, el panel y el contenedor

Revisá `src/vigia/api/` (app, routes, security, storage, jobs, models),
`web/src/`, `Dockerfile`, `docker-compose.yml`, `.dockerignore`. Modelo de
amenaza: la API se expone en internet detrás de Caddy con `VIGIA_API_KEY`
seteada, y también el caso "alguien la deja sin clave en una red local".

Hipótesis concretas que tenés que confirmar o descartar (las vi en una
lectura rápida; **no las des por ciertas**):

1. **Comparación de la clave de API** en `security.require_api_key`: usa `!=`
   en vez de `hmac.compare_digest`. Evaluá el riesgo real de timing attack en
   este contexto.
2. **Inyección de patrones glob vía `dataset_id`**: `storage.dataset_path` y
   `storage.delete_dataset` hacen `_STORAGE_DIR.glob(f"{dataset_id}.*")` con un
   `dataset_id` que llega sin validar desde el cuerpo JSON (`AuditRequest`,
   `PoisonRequest`, `DriftRequest`). ¿Qué pasa con `dataset_id="*"`, `"?"*32`,
   `"[0-9a-f]*"`, `"../algo"`, `"**/x"`? ¿Se puede auditar o **borrar** el
   dataset de otro usuario? Reproducilo levantando la API.
3. **Limitador de peticiones**: la identidad es el valor crudo de `X-API-Key`.
   Sin clave configurada, ¿se evade rotando la cabecera? ¿El diccionario
   `_hits` crece sin límite con claves arbitrarias (DoS de memoria)? El upload
   (`POST /datasets`) **no** tiene límite de peticiones: evaluá llenado de disco
   con subidas de 500 MB.
4. **Subidas huérfanas**: un dataset subido que nunca se usa en un job solo se
   borra al salir el proceso (`atexit`). Con SIGKILL/OOM o reinicio del
   contenedor, el volumen persiste y `_remove_stale_empty_dirs` solo borra
   directorios vacíos. Evaluá agotamiento de disco.
5. **Bloqueo del event loop**: `save_upload` es `async` pero
   `_validate_content` llama a `pl.read_csv`/`pl.read_parquet` sincrónicos
   sobre el archivo completo, en el hilo del loop. Medí cuánto bloquea con un
   CSV grande y qué pasa con otras peticiones concurrentes (incluido `/health`).
   Evaluá también el pico de memoria de leer el archivo entero solo para
   validarlo.
6. **Carrera entre jobs que comparten dataset**: dos jobs con el mismo
   `dataset_id`; el primero en terminar borra el archivo mientras el segundo lo
   lee. Reproducilo.
7. **Fuga de información en errores**: `jobs.run_job` y
   `storage._validate_content` devuelven `f"{type(exc).__name__}: {exc}"` al
   cliente. ¿Pueden exponer rutas del servidor, contenido del archivo u otros
   detalles internos? El docstring dice que no se filtran detalles: verificalo.
8. **Enlace al reporte HTML en el panel**: `Result.tsx` abre
   `auditReportHtmlUrl(jobId)` con un `<a href>`, que no puede mandar la
   cabecera `X-API-Key`. Con la clave configurada, ¿el botón da 401 siempre?
   (Esto es un bug funcional que el CI no detecta.)
9. **Clave embebida en el bundle**: `VITE_API_KEY` se resuelve en build time y
   queda en el JS público. ¿La documentación lo advierte? ¿Dónde guarda el panel
   la clave pegada por el usuario?
10. **CORS**: `allow_credentials=True` con `allow_headers=["*"]` y orígenes
    configurables por env. Evaluá configuraciones peligrosas (p. ej. alguien
    pone `*`).
11. **Autorización entre clientes**: hay una sola clave compartida y los
    `job_id`/`dataset_id` son UUID4. ¿Hay algún endpoint que enumere o que
    permita acceder a recursos ajenos? ¿Los reportes devueltos contienen
    ejemplos de filas reales (IPs, etc.) — es aceptable?
12. **Jobs sin caducidad ni tope**: confirmá el impacto concreto (memoria por
    reporte, número de hilos simultáneos de `asyncio.to_thread`, qué pasa con
    10 auditorías de 1 M de filas a la vez en 8 GB).
13. **XSS**: `report/render.py` escapa con `html.escape(quote=True)`. Buscá
    cualquier interpolación sin escapar (atributos `style`, `color`, números
    formateados, `dataset_path`, claves de `metric`, nombres de columna en
    ejemplos). En el panel, buscá `dangerouslySetInnerHTML` o equivalentes.
14. **Validación de contenido**: `pl.read_csv(..., ignore_errors=True)` acepta
    casi cualquier cosa como CSV. ¿La validación "de contenido" realmente
    rechaza archivos que no son CSV? ¿Hay vectores de parser (Parquet
    malicioso, CSV con millones de columnas, líneas gigantes, zip bombs en
    Parquet comprimido)?
15. **Contenedor**: imágenes base sin digest fijado, `curl` en runtime, usuario
    sin privilegios (verificá permisos reales), `HEALTHCHECK`, `TMPDIR`,
    qué archivos entran a la imagen (`.dockerignore`), `uvicorn` sin
    `--proxy-headers` detrás de Caddy (afecta `request.client.host` del rate
    limit).
16. **StaticFiles en `/`**: rutas del SPA (deep links de react-router) dan 404
    al recargar? ¿El mount puede sombrear rutas de la API?

Además de esas, buscá activamente lo que yo no vi: deserialización insegura,
path traversal en CLI (`--out`, `--report`, perfiles por nombre en
`load_profile`), YAML inseguro, uso de `subprocess`, lectura de PCAP con
nfstream, symlinks en carpetas de entrada, etc.

### Fase 2 — Corrección de los checks y validez científica

Esta es la parte que más importa para el valor del proyecto: si un check da un
falso negativo, la herramienta le dice a alguien que su dataset está limpio
cuando no lo está, que es exactamente el modo de fallo que Vigía existe para
evitar.

Para **cada** check del auditor (`checks/*.py`), cada detector de
envenenamiento (`poison/*.py`) y cada check de deriva (`drift/*.py`):

- Leé la implementación línea por línea y compará con lo que dice
  `docs/CHECKS.md` / `docs/ENVENENAMIENTO.md` / `docs/DERIVA.md`.
- Pensá casos borde: dataset vacío, una sola fila, una sola clase, todas las
  etiquetas nulas, columnas todas nulas, NaN vs null vs inf (Polars los trata
  distinto en `hash_rows`, `n_unique`, comparaciones), floats `-0.0` vs `0.0`,
  strings con espacios/mayúsculas, tipos mixtos, columnas categóricas, split con
  valores inesperados ("Train", "TEST", "val", nulos), etiquetas numéricas,
  timestamps con zonas horarias o formatos ambiguos, IPs IPv6.
- Umbrales: ¿están justificados? ¿Están documentados? ¿Son configurables?
  ¿Cambian el semáforo de forma razonable?
- **Duplicados**: `core/hashing.row_hashes` usa `hash_rows()` de 64 bits; ¿hay
  algún check que trate igualdad de hash como igualdad de fila sin verificar?
  Calculá la probabilidad de colisión a 16 M de filas y decí si importa.
  ¿Cómo hashea `hash_rows` NaN y null? ¿Dos filas con NaN en la misma columna
  se consideran duplicadas (deberían, según la semántica del proyecto)?
- **Columnas de rol** (`declared_roles`, `hash_cols`, `feature_cols`): verificá
  que la lógica descrita en el README ("las declaradas salen del hash; las
  detectadas por nombre no") se cumple en todos los checks, incluido el modo
  `--streaming` (`core/streaming.py`), que reimplementa varios checks: buscá
  divergencias entre la versión eager y la streaming.
- **Fuga** (`leak.temporal`, `leak.host`, `leak.session`): ¿la definición de
  solapamiento es correcta? ¿Qué pasa con splits que no son train/test?
- **`labels.noise`** (cleanlab): ¿las probabilidades son out-of-sample
  (validación cruzada)? Si no, el ruido se subestima. ¿La "cota de
  sobreestimación" que declara tiene sustento?
- **`shortcut.single_feature`**: ¿cómo mide "predice demasiado bien"? ¿Hay fuga
  en esa misma medición (entrenar y evaluar sobre las mismas filas)?
- **Envenenamiento**: ¿`_feature_matrix` y la caché `ctx.shared` producen
  resultados consistentes sin importar el orden en que corren los detectores?
  ¿`combine.py` normaliza correctamente puntajes de escalas distintas? ¿El
  simulador (`simulate.py`) produce ataques realistas o tan fáciles que los
  números de detección están inflados?
- **Deriva** (`drift/metrics.py`): verificá PSI (bins vacíos, epsilon,
  columnas constantes, bins con cuantiles repetidos), KS y JS contra
  implementaciones de referencia (scipy) con datos sintéticos. Reportá
  discrepancias numéricas concretas.
- **Benchmark antes/después** (`benchmark.py`): ¿el modelo se ajusta solo con
  train? ¿Hay preprocesamiento ajustado sobre todo el dataset? ¿La
  comparación es justa (mismo split, misma semilla, mismas filas de test
  después de aplicar fixes que borran filas)? Un fix que borra duplicados del
  test cambia el conjunto de evaluación: ¿se tiene en cuenta?
- **Correcciones** (`fixes/`): ¿alguna puede borrar datos en silencio o
  sobrescribir el archivo original? ¿`quarantine_noise` realmente nunca borra?
  ¿`temporal_split` / `group_split` producen splits sin fuga?
- **Semáforo** (`Report.traffic_light`): revisá su semántica con hallazgos
  `info` y checks saltados por "error interno" (¿un check que crashea debería
  poder dar gris en vez de algo más visible?).
- **Motor** (`core/engine.py`): un check que lanza excepción queda como
  "saltado". ¿Se distingue en el reporte/semáforo un check saltado por
  diseño de uno que falló por bug?

Para los hallazgos de esta fase, escribí **tests mínimos de reproducción** (en
un directorio temporal) con datos sintéticos que muestren el comportamiento
incorrecto.

### Fase 3 — Afirmaciones vs. evidencia

- Contrastá cada número del README, `CHANGELOG.md`, `docs/*.md` y
  `benchmarks/RESULTADOS.md` con el código y con los scripts de `benchmarks/`
  que supuestamente lo producen: cantidad de checks (25 = 17+4+4), fixes (8),
  tests (268), perfiles (6), afirmaciones de rendimiento (pico 5,4 GiB con 1 M ×
  80 columnas, `dup.near` 5× más rápido, cobertura de la muestra de `dup.near`),
  resultados sobre datasets reales. No podés re-correr los benchmarks con datos
  reales: evaluá si el script **produciría** ese número (semilla fija, mismo
  código, sin pasos manuales no documentados) y marcá los que no son
  reproducibles.
- Contrastá la implementación con los requisitos P0/P1 de `vigia.md`. Listá los
  requisitos que el README da por cumplidos pero que están incompletos.
- Verificá que los perfiles YAML (`profiles/*.yaml`) sean coherentes con lo
  que `vigia.load` espera (claves desconocidas que se ignoran en silencio,
  columnas que no existen, ventanas de ataque mal formateadas).

### Fase 4 — Calidad de las pruebas

- Con el reporte de cobertura, identificá rutas de error y ramas críticas sin
  probar (especialmente en `api/`, `core/streaming.py`, `fixes/`, `poison/`).
- Buscá tests que **no pueden fallar**: asserts triviales, mocks que
  reemplazan justo lo que se quería probar, tests que solo comprueban que no
  hay excepción, umbrales tan laxos que cualquier resultado pasa.
- ¿Hay tests de propiedades/invariantes donde tendría sentido (p. ej. "aplicar
  `drop_duplicates` y re-auditar nunca da `dup.exact`")?
- ¿Los tests de la API cubren autenticación activada, los casos de la Fase 1,
  y concurrencia?
- ¿Hay tests que dependen del orden, del reloj, de la red o del sistema
  operativo?

### Fase 5 — Rendimiento y escala

- Identificá operaciones O(n²), materializaciones a Python (`to_list`,
  `to_dicts`, `iter_rows`, `map_elements`/`apply`) sobre columnas completas, y
  copias innecesarias del DataFrame.
- `AuditContext` cachea `row_hash`, `full_row_hash`, `feature_cols`, etc. con
  `cached_property`: ¿algún código muta `ctx.df` o `ctx.label_col` después y
  deja cachés inconsistentes (fixes encadenados, `apply_label_groups`,
  `audit(seed=...)` que muta el contexto)?
- Estimá el pico de memoria de una auditoría completa en función de filas ×
  columnas y compará con la afirmación de `docs/USO.md`.
- Medí con un dataset sintético de 1 M de filas (generado por vos) el tiempo
  por check y señalá los 3 cuellos de botella principales.

### Fase 6 — CI, release y cadena de suministro

- `release.yml`: ¿corre los tests antes de publicar? ¿Verifica que el tag
  coincide con `version` de `pyproject.toml` y con `vigia.__version__` (hoy
  están duplicadas a mano)? ¿Las actions están fijadas por SHA o por tag
  mutable? ¿Permisos mínimos (`permissions:` a nivel de workflow)?
- `ci.yml`: ¿falta `permissions: contents: read`? ¿Se construye y se lintea el
  front (`npm run build`, `npm run lint`) o solo se compila dentro de Docker?
  ¿Se prueba la instalación del wheel (no editable) en un entorno limpio?
  ¿Se prueba el paquete sin el extra `ml` (los checks deben quedar "saltados",
  no crashear)?
- Dependencias: corré `pip-audit` sobre el venv y `npm audit` en `web/`.
  Revisá rangos de versión demasiado abiertos (`polars>=1.0` sin techo, con una
  librería que cambia API seguido) y el riesgo de que `hash_rows` o la
  inferencia de esquemas cambien entre versiones de Polars.
- Empaquetado: construí el wheel y el sdist en un directorio temporal,
  inspeccioná qué archivos incluyen (¿entran los YAML de perfiles? ¿entra algo
  que no debería?) e instalalo en un venv limpio para correr `vigia --help`,
  `vigia checks` y una auditoría sobre un CSV sintético.
- Metadatos: classifier "Development Status :: 3 - Alpha" con versión 1.0.0.

### Fase 7 — Diseño, mantenibilidad y documentación

- Acoplamientos problemáticos, duplicación de lógica (especialmente
  eager vs. streaming, y validación de extensiones entre CLI y API), estado
  global a nivel de módulo (`_STORAGE_DIR` creado al importar, `_STORE`,
  `_rate_limiter`, `_REGISTRY`) y su efecto en tests y en multi-worker
  (`uvicorn --workers N` rompería la cola en memoria: ¿está documentado?).
- Contrato del JSON de salida: ¿está versionado? ¿Un cambio rompería a quien
  lo consume en CI?
- Experiencia de uso de la CLI: códigos de salida, mensajes de error, compatibilidad
  con la consola de Windows (cp1252).
- Documentación desactualizada o contradictoria entre README, USO, PLAN y
  CHANGELOG.

---

## Severidad

Usá esta escala y justificá cada asignación con impacto + probabilidad:

- **Crítica**: compromete datos o el host, o hace que la herramienta dé "limpio"
  sobre un dataset con un defecto grave de forma reproducible. Bloquea la 1.0.
- **Alta**: explotable con esfuerzo moderado, pérdida/corrupción de datos,
  resultados científicos incorrectos en casos comunes. Bloquea el despliegue
  público o la 1.0.
- **Media**: bug real con impacto acotado, DoS que requiere condiciones,
  afirmación documental falsa que confunde al usuario.
- **Baja**: robustez, casos borde raros, endurecimiento recomendado.
- **Info**: observaciones de diseño y mejoras sin defecto concreto.

---

## Entregable

Escribí un único archivo `AUDITORIA-1.0.md` en la raíz del repositorio
(`Data/`), en español, con esta estructura:

1. **Resumen ejecutivo** (máx. 15 líneas): veredicto claro sobre dos preguntas
   separadas — *¿se puede publicar la 1.0.0 en PyPI?* y *¿se puede desplegar la
   API en internet?* — con los hallazgos que bloquean cada una.
2. **Tabla de hallazgos**: ID (`SEC-01`, `COR-01`, `SCI-01`, `DOC-01`,
   `TEST-01`, `PERF-01`, `CI-01`, `DIS-01`), severidad, estado
   (CONFIRMADO/PROBABLE), título de una línea, archivo:línea. Ordenada por
   severidad.
3. **Detalle de cada hallazgo**, con:
   - Ubicación exacta (`ruta/archivo.py:línea`, una o varias).
   - Descripción del defecto.
   - **Escenario de fallo concreto**: entrada/estado → resultado incorrecto.
   - **Reproducción**: comando, request o test mínimo, y la salida observada.
   - Impacto.
   - Recomendación de corrección concreta (qué cambiar y dónde; podés incluir
     un fragmento de código, pero no apliques el cambio).
   - Test que debería agregarse para que no vuelva.
4. **Hipótesis descartadas**: cada una con una línea explicando por qué no es
   un problema (incluí las de la Fase 1 que resulten falsas).
5. **Áreas revisadas sin hallazgos**: qué miraste y por qué concluís que está
   bien.
6. **Plan de remediación priorizado**: tres bloques — *antes de taggear
   v1.0.0*, *antes de desplegar*, *después* — con estimación gruesa de esfuerzo
   por ítem.
7. **Anexo**: salida de la línea base (pytest, ruff, mypy, cobertura,
   pip-audit, npm audit) y los scripts de reproducción usados.

Al terminar, respondé en el chat solo con: el veredicto de las dos preguntas,
el conteo de hallazgos por severidad y la ruta del reporte.
