# Verificación independiente de la remediación de Vigía (antes de mergear y taggear)

## Tu rol

Sos un revisor que **no** participó en las correcciones. Dos tandas de trabajo
corrigieron los hallazgos de la auditoría de Vigía (`vigia-nids` 1.0.0, todavía
no publicada) en 56 commits y unas 4.700 líneas cambiadas. Quien escribió los
arreglos también escribió los tests y verificó su propio trabajo. Tu trabajo es
la mirada externa que faltó: confirmar que cada corrección hace lo que dice, que
no rompió nada que antes funcionaba, y que el código nuevo no trae problemas
propios. Después de tu revisión, Joshua mergea las ramas, empuja y taggea la
v1.0.0, y eso no tiene vuelta atrás.

Sé escéptico con los resúmenes. Las secciones 8 y 9 de `AUDITORIA-1.0.md` y los
mensajes de commit dicen "corregido": verificá cada afirmación contra el código
y los tests, no contra el texto. Un test que pasa no prueba que el arreglo sea
correcto: puede probar otra cosa, o lo mismo que el código ya hacía.

Pensá a fondo cada hallazgo antes de reportarlo. Preferí pocos hallazgos
verificados a muchos posibles.

---

## Contexto (verificado el 05/10/2026)

- Repo en `Data/`; el paquete en `vigia/`; el venv en `vigia/.venv`.
- Ramas, sin mergear y sin push:
  - `main` (`35da75a`): el estado auditado.
  - `auditoria-1.0`: 37 commits sobre `main`, correcciones científicas y de
    corrección (sección 8 del reporte).
  - `despliegue-1.0`: 19 commits sobre `auditoria-1.0`, API, panel, Docker,
    Caddy y CI (sección 9).
- Estado en `despliegue-1.0`: 411 tests pasan (antes 268), cobertura 93 %,
  ruff y mypy limpios. Lo comprobé.
- `AUDITORIA-1.0.md` y los `prompt-*.md` de la raíz están sin versionar.
- Las decisiones de Joshua que ya están tomadas: no las cuestiones, verificá que
  estén bien implementadas.
  - `time_format` público.
  - `drift.concept` real; el check adversario pasa a llamarse `drift.covariate`.
  - `errors` y `schema_version` en el JSON.
  - Classifier Beta.
  - Semáforo rojo si un check falla.
  - Límite de subida de 200 MB.
  - Un trabajo a la vez, con cola de 4 y 503 cuando se llena.
  - `n_rows` exacto.
  - `VIGIA_ENV=production` exige `VIGIA_API_KEY`.

---

## Reglas

1. **Solo lectura.** No modifiques archivos versionados, no commitees, no
   hagas push, tag, merge ni rebase, no publiques nada. Escribí scripts y
   tests de prueba fuera del repo (directorio temporal) y decí cómo se corren.
2. Podés correr pytest, ruff, mypy, `npm run build`/`lint`, `docker build`,
   levantar `vigia serve` o el compose de producción en local, y pegarles con
   curl/httpx. Si Docker Desktop está apagado, avisá en vez de dar por
   verificado lo que necesita Docker.
3. No descargues datasets reales; usá datos sintéticos.
4. Clasificá cada hallazgo como **CONFIRMADO** (reproducido) o **PROBABLE**
   (razonamiento sólido, sin poder ejecutarlo). Lo que no llegue a probable se
   descarta, pero se lista con una línea de por qué.

---

## Qué revisar, en este orden

### 1. Integridad de las ramas
- `git log --oneline main..despliegue-1.0`: ¿todos los commits pasan la suite
  por separado? No hace falta correrla en los 56: corré la suite completa en
  `auditoria-1.0`, en `despliegue-1.0` y en al menos 6 commits intermedios
  elegidos por riesgo (los que cambian `core/`, `findings.py`, `storage.py`,
  `jobs.py` y `app.py`). Usá `git worktree add` en un directorio temporal para no
  tocar el árbol de trabajo.
- ¿Algún commit mezcla cambios no relacionados o deja el árbol roto a la mitad?
- ¿Hay archivos que no deberían estar versionados (secretos, `.env`, salidas,
  binarios, scripts temporales)? Revisá en especial `deploy/`.

### 2. Cada corrección contra su hallazgo
Para cada fila de las tablas de las secciones 8 y 9:
- Leé el hallazgo original (sección 3), el diff del commit indicado y el test.
- Respondé tres preguntas:
  1. ¿El test falla en el código anterior? Comprobalo corriéndolo contra el
     commit padre (`git worktree`), al menos para todos los críticos y altos.
  2. ¿La corrección cubre el caso general o solo el ejemplo del test?
  3. ¿Introduce un modo de fallo nuevo?
- Volvé a correr las reproducciones del anexo 7.2 (el núcleo está en la
  sección 3 de cada hallazgo) contra `despliegue-1.0`.

Atención especial a:
- **SEC-01:** que ningún camino llegue a `storage` sin pasar por la
  validación: path params, `job_id`, `reference_id`, llamadas internas.
- **SCI-01/02 (`time_format`):** que la detección de ambigüedad no dé falsos
  "ambiguo" con fechas ISO, epoch o datetime nativos, y que el umbral de valores
  sin interpretar esté justificado.
- **SCI-03 (`drift.concept` nuevo):** ¿cómo entrena y evalúa? ¿Hay fuga entre
  referencia y lote? ¿Qué hace con clases que están en el lote y no en la
  referencia, con una sola clase, con lotes chicos? ¿Los umbrales (caída de
  0,10 y 0,25) dan falsos positivos con dos muestras de la **misma**
  distribución? Medilo con varias semillas.
- **SCI-05:** falsos positivos de la discretización en columnas continuas
  ruidosas, con distintos tamaños de muestra y cantidad de bins.
- **SCI-04:** que `compare()` evalúe de verdad sobre las mismas filas de test.
- **SCI-07:** que leer `Infinity`/`NaN` como valores no rompa columnas de texto
  que contienen esas palabras ni la inferencia de enteros.
- **COR-05:** que ningún camino (CLI, API, HTML, panel, `--streaming`) muestre
  verde o gris cuando hubo un error.

### 3. El código nuevo de la segunda tanda, como código nuevo
Revisalo con el mismo rigor que la auditoría original. Modelo de amenaza:
servidor de 8 GB detrás de Caddy, clave compartida, atacante sin clave en
internet y cliente con clave que se porta mal.

- **`api/config.py`:** validación al arrancar; qué pasa con valores límite (0,
  negativos, enormes, vacíos).
- **Middleware de tamaño:** `Content-Length` falso (menor que el real, mayor,
  negativo, repetido), `chunked`, cuerpo cortado a la mitad, peticiones que no
  son a `/datasets`. ¿Deja archivos temporales a medias?
- **TTL de subidas, cuota y limpieza al arrancar:** carreras entre la tarea
  periódica y un trabajo que empieza a leer el dataset; un dataset en cola que
  caduca; la cuota contada antes o después de escribir; candados
  (`fcntl.flock` en Linux, `msvcrt` en Windows): ¿la rama de Linux es
  correcta? Si podés, corré esos tests en Linux con Docker
  (`docker run -v ...:/src python:3.12-slim ...`). Hoy solo se vieron pasar en
  Windows.
- **Cola y tope de trabajos:** que un trabajo que falla o lanza
  `BaseException` libere su lugar; qué pasa con la cola llena; no hay tope de
  tiempo por trabajo (problema 5 de la sección 9): medí el impacto real (¿un
  cliente con clave puede bloquear la cola para siempre con un dataset
  armado a propósito?).
- **Caducidad de reportes y 410:** memoria acotada de verdad (¿se borran
  también los ids caducados, o la lista de "caducados" crece sin fin?).
- **Limitador:** identidad por IP con `--proxy-headers`: ¿se puede falsificar
  `X-Forwarded-For` si alguien llega a la API sin pasar por Caddy? Comprobá
  que en `deploy/docker-compose.prod.yml` la API no es alcanzable desde afuera
  y que `--forwarded-allow-ips` no es `*`.
- **Errores con id de correlación:** ¿queda algún camino que devuelva
  `str(exc)` al cliente?
- **Fallback de SPA:** que no sirva `index.html` para rutas de la API, que no
  permita path traversal en archivos estáticos (`/..%2f..`, `%5c` en Windows).
- **Panel:** el reporte abierto desde un `Blob` comparte origen con el panel
  (problema 3). Comprobá si la CSP del `Caddyfile` se aplica al documento
  `blob:` (en Chrome hereda la política de quien lo crea) y si eso bloquea
  scripts dentro del reporte. Decí qué pasa sin Caddy.
- **Dockerfile, compose de producción y `Caddyfile`:** digests reales (que
  existan, no que tengan forma de digest), usuario sin privilegios, sistema de
  archivos, `mem_limit` (6 GB para la API: ¿alcanza para el pico medido de
  5,4 GiB más la cola?), HSTS, CSP compatible con el build de Vite (¿el panel
  usa estilos o scripts en línea que la CSP bloquee?), `request_body max_size`
  y el problema 7 (Caddy rechaza un archivo de exactamente el límite).
- **`ci.yml` y `release.yml`:** sintaxis y lógica. Que los SHA de las actions
  existan (`gh api repos/<owner>/<repo>/commits/<sha>`), permisos mínimos y
  que los jobs nuevos corran con lo que instalan. Usá `actionlint` si lo podés
  instalar sin tocar el repo.

### 4. Regresiones
- Comparando con `main`: ¿algún comportamiento documentado que antes
  funcionaba cambió sin quedar en el CHANGELOG? Fijate en especial en:
  - el formato del JSON (ids de checks renombrados como `drift.covariate`,
    campos nuevos);
  - los códigos de salida;
  - las opciones de la CLI;
  - los endpoints y sus respuestas.
- Corré los benchmarks sintéticos que existen
  (`benchmarks/control_limpio.py`, `make_demo_dataset.py`) en `main` y en
  `despliegue-1.0` y compará los hallazgos. Toda diferencia tiene que
  explicarse por un arreglo.
- Rendimiento: medí la auditoría completa sobre 1 M de filas sintéticas en las
  dos ramas (tiempo y pico de memoria). La discretización de SCI-05 y
  `drift.concept` son las sospechosas.
- Instalá el wheel de `despliegue-1.0` en un venv limpio, sin `[ml]`, y corré
  `vigia audit`, `vigia fix`, `vigia drift` y `vigia checks`.

### 5. Documentación y CHANGELOG
- ¿El `[Unreleased]` del CHANGELOG cubre todo lo que cambió para el usuario, y
  no promete nada que el código no haga?
- ¿README, USO, CHECKS, DERIVA, ARQUITECTURA, PLAN y DESPLIEGUE coinciden entre
  sí y con el código? Conteos de checks y tests, códigos de salida, variables
  de entorno, códigos HTTP.
- ¿`docs/DESPLIEGUE.md` alcanza para que alguien que nunca vio el proyecto lo
  despliegue? Seguilo paso a paso en local, hasta donde se pueda sin un
  servidor ni un dominio reales.

### 6. Clasificar lo que queda abierto
Para cada problema abierto de las secciones 8 y 9, y para cada hallazgo nuevo
tuyo, decí si **bloquea el tag v1.0.0**, si **bloquea el despliegue** o si
**puede esperar**, con una línea de justificación. Tomá posición explícita
sobre:
- el problema 5 (sin tope de tiempo por trabajo);
- el problema 1 (recargar el panel pierde la clave): ¿`sessionStorage` sería
  un riesgo aceptable?;
- SEC-07 (filas e IPs reales en los reportes, con una clave compartida).

---

## Entregable

Un archivo `VERIFICACION-1.0.md` en la raíz del repo (`Data/`), en español,
con:

1. **Veredicto** en pocas líneas, respondiendo por separado:
   - ¿Se pueden mergear las dos ramas en `main`?
   - ¿Se puede taggear la v1.0.0?
   - ¿Se puede desplegar?
   En cada caso, con lo que bloquea.
2. **Tabla de verificación** por ID: `ID | ¿el test falla antes del arreglo? |
   ¿la corrección es completa? | veredicto (OK / incompleto / regresión) |
   nota`.
3. **Hallazgos nuevos**, con el mismo formato que la auditoría original:
   - ID con prefijo `VER-`;
   - severidad;
   - estado;
   - ubicación;
   - escenario de fallo;
   - reproducción;
   - corrección sugerida;
   - test que habría que agregar.
4. **Regresiones y diferencias** entre `main` y `despliegue-1.0` (benchmarks,
   rendimiento, contrato).
5. **Hipótesis descartadas** y **áreas revisadas sin hallazgos**.
6. **Clasificación de lo abierto** (punto 6) y una lista ordenada de pasos
   hasta el tag y el despliegue.
7. **Anexo** con los comandos, scripts y salidas.

En el chat, respondé solo con los tres veredictos, el conteo de hallazgos
nuevos por severidad y la ruta del archivo.
