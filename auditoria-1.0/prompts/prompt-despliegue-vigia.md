# Remediación de Vigía, segunda tanda: bloque "antes de desplegar"

## Tu rol

Sos el ingeniero que deja la API y el panel de Vigía listos para exponerse en
internet. La auditoría está en `AUDITORIA-1.0.md` (raíz del repo `Data/`), y su
sección 8 registra la primera tanda de correcciones, ya hecha y verificada.
Leé el reporte completo, incluida la sección 8, antes de tocar nada: es la
fuente de verdad sobre qué está mal, cómo se reproduce y qué se sugiere.

El modelo de amenaza es concreto: un servidor Hetzner CX33 (4 vCPU, 8 GB de
RAM, disco de 80 GB) con Docker Compose y Caddy delante para HTTPS, y la API
con `VIGIA_API_KEY` seteada. Los clientes son pocos y comparten una sola
clave. El atacante que importa es cualquiera en internet (sin clave) y
cualquiera que tenga la clave y se porte mal o tenga un bug. La pregunta que
manda en cada corrección es: **¿puede un cliente, con o sin clave, tumbar el
servidor, llenarle el disco o la memoria, o ver o borrar datos de otro?**

Pensá cada corrección a fondo antes de escribirla. Cambios mínimos, en el
estilo del código existente, sin dependencias nuevas salvo que no haya otra
salida (y en ese caso preguntá).

---

## Estado de partida (verificado el 05/10/2026)

- La rama `auditoria-1.0` tiene 37 commits sobre `main` con la primera tanda:
  SEC-01 (ids validados con `^[0-9a-f]{32}$` en `api/models.py` y
  `storage._candidates` sin glob), SEC-11 (`hmac.compare_digest`), los
  hallazgos científicos, `Report.errors` + `schema_version`, código de salida 3,
  `release.yml` endurecido y documentación al día.
- 352 tests pasan; ruff, `ruff format --check` y mypy limpios; cobertura 92,15 %.
  El venv está en `vigia/.venv`.
- `AUDITORIA-1.0.md` y los archivos `prompt-*.md` de la raíz están sin
  versionar. No los commitees salvo que Joshua lo pida.
- Convenciones que tenés que respetar:
  - Todo en español rioplatense, con voseo: código, docstrings, mensajes,
    tests y commits.
  - Los docstrings explican el **porqué**. Imitá el tono de los que ya
    existen: cada uno cita el hallazgo que motivó el cambio
    (`AUDITORIA-1.0.md, SEC-xx`).
  - Todo el texto de `src/` cabe en cp1252 (hay un test).
  - Línea máxima de 100 caracteres.
  - Commits según el skill `commits-auditables`: uno por acción, la mayor
    granularidad sin romper el árbol, con un mensaje que explique el porqué en
    el formato del historial (`fix(api): ...`, `docs(uso): ...`). Cada commit
    pasa la suite completa.

---

## Reglas (no negociables)

1. **Rama:** si `auditoria-1.0` ya está mergeada en `main`, creá
   `despliegue-1.0` desde `main`. Si no, creala desde `auditoria-1.0`. No
   mergees ni rebasees nada por tu cuenta.
2. **Nunca** hagas `git push` ni `git tag`, no publiques a PyPI ni a GHCR, no
   toques un servidor real, no compres dominios ni crees cuentas. Los archivos
   de despliegue se escriben y se prueban **en local**.
3. **Test primero:** para cada hallazgo, escribí el test que lo reproduce,
   confirmá que falla por el motivo correcto y recién ahí corregí. Si el test
   pasa sin cambios, pará e investigá: no arregles lo que no está roto.
4. Después de cada corrección: `pytest -q`, `ruff check src tests`,
   `ruff format --check src tests`, `mypy src`; y `npm run build` +
   `npm run lint` en `vigia/web` si tocaste el panel. Todo verde antes de
   commitear.
5. Los tests de límites, tiempos y caducidad tienen que ser **deterministas y
   rápidos**: reloj inyectable (o `time.monotonic` parcheado), tamaños chicos
   con límites configurados chicos por variable de entorno, nada de `sleep`
   largos. La suite no puede crecer más de ~15 s.
6. **No amplíes el alcance.** Lo nuevo que encuentres va al resumen final.
7. **Decisiones que no son tuyas** (marcadas con ⚠): preguntá con opciones
   concretas y una recomendación, y seguí con otro ítem mientras tanto.
8. No debilites tests existentes. Si uno codificaba el comportamiento
   incorrecto, cambialo en el mismo commit y explicalo.

---

## Paso 0 — Preparación

1. Leé `AUDITORIA-1.0.md` completo, `vigia/docs/USO.md` (sección API),
   `vigia/docs/PLAN.md` (sección "Despliegue") y todo `vigia/src/vigia/api/`.
2. Corré la línea base y confirmá 352 passed.
3. Creá la rama según la regla 1.

---

## Paso 1 — Correcciones, en este orden

### 1.1 Configuración centralizada y límites seguros por defecto

Hoy cada límite se lee de `os.environ` en un lugar distinto. Antes de agregar
más, juntalos en un solo lugar (un módulo `api/config.py` o funciones en
`security.py`; elegí lo que menos mueva) que lea y valide al arrancar:
`VIGIA_MAX_UPLOAD_MB`, `VIGIA_RATE_LIMIT_PER_MINUTE`, más los nuevos de esta
tanda (tope de trabajos, TTL de subidas, TTL de reportes, cuota de disco).
Valores inválidos (negativos, no numéricos) hacen fallar el arranque con un
mensaje claro, no un `ValueError` en la primera petición.

- ⚠ **Decisión:** el valor por defecto de `VIGIA_MAX_UPLOAD_MB`. PLAN.md pide
  bajarlo de 500. Recomendación: 200 MB por defecto en el código, documentar
  cómo subirlo, y dejar el valor explícito en el compose de producción.
  Preguntá antes de fijarlo.

### 1.2 SEC-05: el límite de subida corta el stream de verdad
- Un middleware ASGI propio (sin dependencias) que rechace con 413 por
  `Content-Length` declarado y que cuente los bytes del cuerpo y corte
  cuando superan el límite (también con `Transfer-Encoding: chunked`, sin
  `Content-Length`). Solo sobre `POST /api/v1/datasets`; el resto de las rutas
  con un tope chico para los cuerpos JSON.
- El límite real en producción va también en Caddy (1.10); el middleware es
  la defensa para quien corra la imagen sin Caddy.
- Corregí el docstring de `save_upload` y lo que diga `USO.md`.
- Test: con `VIGIA_MAX_UPLOAD_MB=1`, un cuerpo de varios MB recibe 413 **sin**
  que se escriba en disco más que el límite (verificá el directorio temporal
  y `TMPDIR`), con y sin `Content-Length`.

### 1.3 SEC-02: subidas huérfanas y disco
- TTL de subidas: un dataset subido que ningún trabajo usa en N minutos se
  borra. Una tarea periódica en el `lifespan` (asyncio, sin dependencias), con
  reloj inyectable para los tests.
- Cuota total del directorio de subidas: si una subida nueva haría superar la
  cuota, 507 (o 413) antes de escribirla.
- Limpieza al arrancar: borrar los directorios `vigia_api_*` de ejecuciones
  anteriores **con** contenido (hoy solo se borran vacíos). Cuidado: en un
  solo contenedor no hay otro proceso vivo usándolos; documentá que con dos
  procesos sobre el mismo `TMPDIR` esto sería destructivo, y protegelo (p. ej.
  un archivo de lock con el PID, o borrar solo directorios más viejos que el
  arranque).
- `POST /api/v1/datasets` pasa por el limitador de peticiones.
- Corregí el comentario del compose sobre el volumen.
- Tests: subida sin trabajo + avanzar el reloj → el archivo desaparece; cuota
  superada → rechazo sin archivo escrito; un directorio viejo con contenido →
  borrado al arrancar; un directorio de esta ejecución → intacto.

### 1.4 Tope de trabajos y caducidad de reportes (PLAN.md)
- Tope de trabajos simultáneos (`VIGIA_MAX_CONCURRENT_JOBS`, por defecto 1 o 2:
  con picos de 5,4 GiB por auditoría de 1 M × 80 en 8 GB, más de 1 es riesgo
  de OOM). Por encima del tope, ⚠ **decisión:** encolar (el trabajo queda
  `pendiente`) o rechazar con 429/503. Recomendación: encolar con un límite de
  cola chico y rechazar con 503 + `Retry-After` cuando la cola está llena.
- Caducidad: `JobStore` borra los trabajos terminados o fallidos (y su
  reporte) después de un TTL; un `GET` de un trabajo caducado da 404 con un
  mensaje que diga que caducó (o 410). Tope de trabajos guardados en memoria.
- Revisá la interacción con 1.3: un dataset que espera en la cola no puede
  caducar por TTL de subida mientras su trabajo está pendiente.
- Tests con reloj inyectable: tope respetado, cola llena → 503, reporte
  caducado → 404/410, dataset en cola no se borra.

### 1.5 SEC-04 y PERF-02: validar sin leer todo
- Parquet: validar con `pl.read_parquet_schema` y los metadatos (filas, tamaño
  descomprimido de los row groups si pyarrow está disponible; si no, un tope
  de filas). Rechazar por encima de un tope de expansión.
- CSV: leer solo una muestra (`n_rows`) para validar que es un CSV y obtener
  el número de columnas; el número de filas, si hace falta, sin materializar
  (`scan_csv(...).select(pl.len())`), o devolverlo como desconocido.
  ⚠ Si `n_rows` deja de ser exacto en `DatasetUploadResponse`, es un cambio de
  contrato: preguntá.
- La validación corre en un hilo (`asyncio.to_thread`), no en el event loop.
- Test: un Parquet de alta compresión (50 M de ceros, ~114 KiB) se rechaza
  sin descomprimirlo; `/health` responde mientras se valida una subida.

### 1.6 COR-06: la API acepta lo mismo que la CLI
- La validación usa el mismo lector que la auditoría (el reintento cp1252 de
  `io/readers`), sobre la muestra de 1.5.
- Test: un CSV en cp1252 con `–` en una etiqueta (como el día de ataques web
  de CIC-IDS2017) sube con 201.

### 1.7 SEC-03: limitador de peticiones
- Identidad: con clave configurada, la IP real del cliente (detrás de Caddy,
  vía `X-Forwarded-For` **solo** si uvicorn corre con
  `--proxy-headers --forwarded-allow-ips` apuntando al proxy); sin clave, la IP.
  Nunca el valor crudo de la cabecera `X-API-Key`.
- Poda de `_hits`: las identidades sin peticiones en la ventana se borran, y
  hay un tope de identidades.
- Tests: rotar la cabecera no evade el límite; `_hits` no crece sin límite con
  10.000 identidades distintas en ventanas pasadas.

### 1.8 SEC-06 y problema nuevo 3 de la sección 8: errores sin detalles internos
- Al cliente (API y panel): mensaje genérico + un id de correlación. En el
  log: tipo, mensaje y traceback con ese id. Aplica a `jobs.run_job`,
  `storage._validate_content` y `Report.errors` cuando el reporte sale por la
  API (en la CLI local el detalle completo sigue siendo útil: no lo quites
  ahí).
- Test: una excepción cuyo mensaje contiene una ruta y un valor de fila no
  aparece en la respuesta HTTP, y sí en el log con el mismo id.

### 1.9 Panel: COR-07, COR-09, COR-10, COR-11, SEC-08
- **COR-07:** "Ver el reporte HTML" con `fetch` + cabecera → `Blob` →
  `URL.createObjectURL` (revocarlo después). Sin tokens en la URL.
- **COR-09:** fallback de SPA en `api/app.py`: las rutas que no empiezan con
  `/api` ni `/health` y no son un archivo estático devuelven `index.html`.
  Test con un `web/dist` mínimo de prueba: `/resultado/abc` → 200 con el
  HTML; `/api/v1/no-existe` → 404 JSON.
- **COR-10:** el comando de "Corregir" usa un marcador `<archivo>` y las
  columnas con que se lanzó la auditoría.
- **COR-11:** claves React únicas (índice + `check_id`).
- **SEC-08:** quitar `VITE_API_KEY` del bundle o advertirlo de forma explícita
  en el código y en la doc; `.dockerignore` excluye `.env` y `web/.env*`.
- **Verificación en navegador:** levantá la imagen o `vigia serve` con el
  build del panel y recorré el flujo completo (subir, auditar, ver el
  resultado, abrir el HTML, recargar un deep link, deriva) con la clave
  configurada. Si tenés una herramienta de navegador disponible (skill
  `built-in-browser`, `chrome-browser` o `run`), usala y sacá capturas; si
  no, decilo en el resumen y dejá los pasos para que Joshua lo haga a mano.

### 1.10 SEC-09, SEC-12 y archivos de despliegue
- **Dockerfile:** imágenes base fijadas por digest (obtenelos con
  `docker buildx imagetools inspect` o la API de Docker Hub; **no los
  inventes**; si no tenés red, dejalo anotado), healthcheck con
  `python -c "import urllib.request..."` en vez de `curl`, `web/dist`
  propiedad de root y solo lectura, uvicorn con `--proxy-headers` y
  `--forwarded-allow-ips` configurable por variable.
- **SEC-12:** `allow_credentials=False`; el arranque falla si
  `VIGIA_CORS_ORIGINS` contiene `*`.
- **El arranque falla sin `VIGIA_API_KEY`** cuando se corre en modo
  producción (p. ej. `VIGIA_ENV=production`, que el compose de producción
  setea). ⚠ Si preferís otro mecanismo, preguntá; lo que no puede pasar es
  que la imagen de producción arranque abierta en silencio.
- **`docker-compose.prod.yml` + `Caddyfile`** (en `vigia/deploy/` o donde
  encaje mejor): Caddy con HTTPS automático para un dominio que se pasa por
  variable, `request_body max_size` igual al límite de la API, cabeceras de
  seguridad (HSTS, `X-Content-Type-Options`, `Referrer-Policy`, una CSP que
  funcione con el build de Vite), la API sin puerto expuesto al host (solo
  Caddy), límites de memoria del contenedor por debajo de 8 GB, `restart`,
  y la imagen referenciada como `ghcr.io/joshua203-byte/vigia-nids:<versión>`
  (sin publicarla).
- Probá el compose de producción en local con un dominio de prueba
  (`localhost` con `tls internal` en Caddy) y verificá con `curl -k`: 401 sin
  clave, 413 por encima del límite, cabeceras de seguridad presentes, deep
  link del panel con 200.
- Un `docs/DESPLIEGUE.md` corto: requisitos del servidor, variables, cómo
  generar la clave, cómo levantar, cómo ver logs, cómo actualizar, qué
  vigilar (disco, memoria) y los límites conocidos (una sola instancia, cola
  en memoria, `--workers` > 1 no soportado). Linkealo desde README y PLAN.

### 1.11 Problema nuevo 1 de la sección 8
- `vigia fix` sale con 1 cuando ninguna corrección se pudo aplicar; debería
  ser 2 (error de uso) según el contrato de `ARQUITECTURA.md`. Test y
  corrección de una línea.

### 1.12 CI-02 parcial: que el CI cubra lo que se despliega
- `ci.yml`: `permissions: contents: read`, actions fijadas por SHA (los
  mismos que ya verificó `release.yml`), un job que corra `npm ci`,
  `npm run lint` y `npm run build` del panel, y que el job de Docker pruebe
  también el 413 y el deep link.
- No agregues todavía la pasada sin `[ml]` ni `pip-audit` (bloque
  "después"), salvo que sea trivial.

### 1.13 Documentación
- `USO.md` (sección API): las variables nuevas, los códigos 413/429/503/507 y
  404/410 por caducidad, la política de un dataset por trabajo, el TTL de
  subidas y de reportes.
- `PLAN.md`: tachá los tres cambios "antes de desplegar" que ya están, y
  actualizá el número de tests.
- `CHANGELOG.md`: todo bajo `[Unreleased]`. No toques `[1.0.0]`.

---

## Fuera de alcance

El bloque "después" de la sección 6 (PERF-01, CI-03, TEST-01 completo,
R6/R7/R8, DIS-01, SEC-07, SEC-10, la pasada sin `[ml]` y `pip-audit`), la
re-medición con datos reales (2.867 infinitos, `drift.concept`) y los
problemas nuevos 2, 4, 5, 6, 7 y 9 de la sección 8 (salvo lo que 1.12 ya cubre
del 2).

---

## Entregable

1. La rama `despliegue-1.0` con un commit por corrección y la suite verde en
   cada uno.
2. Al final: `pytest -q --cov=src` (cobertura ≥ 92 %), ruff, format, mypy,
   `npm run build`, `npm run lint`, `docker build` y el compose de producción
   levantado en local con las comprobaciones de 1.10, todo verde.
3. Una sección **"9. Estado de la remediación (despliegue)"** al final de
   `AUDITORIA-1.0.md`, con la tabla `ID | estado | commit | test` y la lista de
   problemas nuevos sin arreglar.
4. En el chat, solo: qué quedó corregido, qué decisiones ⚠ necesitan
   respuesta, qué falta para desplegar de verdad (dominio, servidor, publicar
   la imagen) y el comando para ver los commits.
