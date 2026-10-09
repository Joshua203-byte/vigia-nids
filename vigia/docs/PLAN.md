# Plan hasta la versión 1.0

Qué falta, en qué orden y cómo hacerlo. Escrito el 22 de septiembre de 2026 y
**actualizado el 9 de octubre de 2026** (1.0.x publicada en PyPI, 428 tests, CI en verde; la 1.0.0 incluye los hallazgos de la auditoría y de su verificación corregidos).
Las fases de abajo se dejan como se escribieron, con una nota de estado al
principio de cada una cuando ya se cumplió; lo que falta de verdad está en
[Qué falta para la 1.0](#qué-falta-para-la-10).

**Índice:** [Dónde estamos](#dónde-estamos) · [Fase 0](#fase-0--empaquetado-medio-día) ·
[Fase 1](#fase-1--escala-2-3-días) · [Fase 2](#fase-2--api-rest-4-5-días) ·
[Fase 3](#fase-3--panel-web-1-2-semanas) · [Fase 4](#fase-4--deuda-tecnica-2-3-días) ·
[Fase 5](#fase-5--p2-abierto) · [Riesgos](#riesgos) · [Orden recomendado](#orden-recomendado)

---

## Dónde estamos

| Pieza | Estado |
|---|---|
| Módulo 1 (auditor) | 16 checks (incluye `dup.near`), validado contra CIC-IDS2017, Engelen et al. y CSE-CIC-IDS2018 |
| Módulo 2 (envenenamiento) | 4 detectores, medidos sobre tráfico real |
| Módulo 3 (deriva) | 5 checks; 4 medidos sobre los 5 días de CIC-IDS2017. `drift.concept` (agregado tras la auditoría) está pendiente de medir sobre datos reales |
| Correcciones | 8, con cuarentena |
| Lectores | CSV, Parquet, Zeek, Suricata EVE, PCAP |
| CLI | con `--profile`, `--streaming` y `vigia serve` |
| API REST | FastAPI, clave de API, límites, trabajos asíncronos |
| Panel web | React + Vite, semáforo gris tan visible como el rojo |
| Docker | imagen única (API + panel), usuario sin privilegios, verificada en CI |
| Perfiles de datasets (R17) | 5 de 5: CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, UGR'16, CTU-13. Auditados con datos reales (archivos oficiales) todos menos UGR'16, del que solo hay una muestra |
| Publicación | `vigia-nids` 1.0.x en PyPI, publicada por `release.yml` con OIDC (tests, prueba de la rueda sin extras y verificación del tag antes de subir). La 0.2.0 está retirada (yanked) por el fallo crítico de la API |
| Tests | 428 (cobertura 93 %), ruff y mypy limpios |

**Estado por fase:** 0 (empaquetado), 1 (escala), 2 (API) y 3 (panel, Docker)
están hechas. La fase 4 está hecha (4.1 y 4.2 ya estaban resueltos). De la
fase 5 solo se hizo "Perfiles por dataset".

## Qué falta para la 1.0

| Pendiente | Depende de | Nota |
|---|---|---|
| ~~Publicar la 1.0~~ | Hecho | La 1.0.0 salió el 06/10/2026 y la 1.0.1 (solo documentación) el 08/10/2026 |
| Re-medir con datos reales | Los CSV de CIC-IDS2017 ya están en `Datadeprueba/` (fuera de git) | `drift.concept` sobre los cinco días. Los infinitos se re-midieron el 06/10/2026 y A, B y C con 10 semillas el 09/10/2026. Declarado como pendiente |
| Desplegar (opcional) | Decidir si hay quién lo use, un dominio y un servidor | Ver "Despliegue" abajo y [`DESPLIEGUE.md`](DESPLIEGUE.md); los archivos ya están y se probaron en local; no bloquea la 1.0, que ya es instalable con `pip` y con `docker compose up` |

**Despliegue.** El panel y la API ya existen; desplegar es ponerlos en un servidor
público. Lo investigado el 02/10/2026: un servidor de Hetzner en Europa (CX33, 4
vCPU, 8 GB, €8,49 al mes) con Docker Compose, Caddy delante para HTTPS y una
clave de API real. Un plan de 4 GB no alcanza: auditar 1 M de filas con 80
columnas tuvo un pico de 5,4 GiB (medido el 04/10/2026, ver `docs/USO.md`). Segunda opción si no se quiere mantener un
servidor: Railway (se paga uso real). Descartadas por precio o por diseño: Cloud
Run (la cola de trabajos vive en memoria), Render, Fly.io, el plan gratuito de
Oracle (reclama las máquinas inactivas) y Cloudflare Tunnel (descifra el tráfico,
que son datasets de red). Los tres cambios de código que hacían falta ya están:
~~un tope de trabajos simultáneos~~, ~~caducidad de los reportes que `JobStore`
guarda en memoria~~ y ~~un `VIGIA_MAX_UPLOAD_MB` más bajo que los 500 MB~~ (200
MB). También están los que agregó la auditoría de la 1.0 (`AUDITORIA-1.0.md`,
bloque "antes de desplegar"): ~~subidas huérfanas y cuota de disco~~, ~~un límite
de subida que corta el stream de verdad~~, ~~el enlace al reporte HTML con clave
de API~~, ~~validar los Parquet sin descomprimirlos~~, el limitador por IP, los
errores sin detalles internos y el panel servido con fallback de SPA. Los
archivos de despliegue (`deploy/docker-compose.prod.yml` y `Caddyfile`) se
escribieron y se probaron en local: ver [`DESPLIEGUE.md`](DESPLIEGUE.md). **Lo
que falta no es código:** un dominio, el servidor, publicar la imagen en GHCR
y mirar el primer despliegue real.

**Límites conocidos que la 1.0 debe declarar, no esconder:**

- Sobre la versión procesada de CSE-CIC-IDS2018 no corren `leak.host`,
  `leak.session` ni `leak.temporal`: no trae IPs ni columna de split.
- `dup.near` sobre 200.000 filas trabaja con una muestra al azar y reporta una
  cota inferior (con el 49 % de las filas ve el 90 % de lo que ve completo,
  con el 10 % el 62 %); `--streaming` solo corre los
  checks de duplicados y validez.
- El `Timestamp` de CSE-CIC-IDS2018 usa reloj de 12 h sin AM/PM: la hora no se
  puede recuperar del archivo (01:45 puede ser 1:45 o 13:45), así que el perfil
  no lo declara como `time_col`.
- `labels.noise` sobreestima con clases muy solapadas: no separa el ruido real
  del solapamiento. El hallazgo declara una cota de cuánto pudo sobreestimar
  según la exactitud del modelo auxiliar (hasta 15 puntos con exactitud < 0,80).
- UGR'16 no se audita con archivos oficiales: `nesg.ugr.es` dio 403 y ninguna
  otra fuente trae flujos (ver `benchmarks/RESULTADOS.md`). El perfil se validó
  solo con una muestra de 5.000 filas.
- La API acepta CSV y Parquet. Si algún día acepta PCAP, hará falta un
  contenedor aislado aparte (hoy la imagen no incluye `nfstream`).

**Requisitos P0 que el diseño (`vigia.md`, sección 6.1) pide y la 1.0 cumple solo
en parte** (hallados por la auditoría, `AUDITORIA-1.0.md`, DOC-01):

- **R5 — atajos.** El criterio de aceptación pide "la precisión de un modelo
  entrenado solo con cada columna". `shortcut.single_feature` mide la exactitud
  balanceada de la regla "clase mayoritaria de cada valor" (de cada tramo por
  cuantil, si la columna es continua), sobre las mismas filas con las que la
  calcula (sin holdout) y solo reporta las columnas que superan el umbral, no
  todas. Una clase más rara que un tramo no se ve.
- **R6 — fuga por sesión.** El diseño (sección 8.4) la define como 5-tupla **más
  ventana de tiempo**. `leak.session` agrupa solo por 5-tupla: una tupla
  reutilizada semanas después cuenta como la misma sesión.
- **R7 — etiquetas dudosas.** Pide una "lista de registros sospechosos con
  puntaje de confianza". El reporte trae hasta 10 ejemplos por hallazgo; la
  lista completa de filas (`row_indices`) no sale en el JSON y solo se obtiene
  por el SDK o apartándola con `quarantine_noise`.
- **R8 — reporte.** Pide que "el JSON valide contra un esquema". El JSON lleva
  `schema_version`, pero no hay un esquema formal (JSON Schema) publicado.
- **`labels.window`** (sección 8.3: etiquetas fuera de la ventana documentada
  del ataque) y su corrección `relabel_window` no están implementadas; los
  perfiles traen las ventanas pero ningún check las usa.

**Lo que ya es deployable:** la CLI en un pipeline de CI o un cron, y la imagen
Docker con `docker compose up`.

---

## Fase 0 — Empaquetado (medio día)

Sin esto, Vigía solo existe en tu máquina. Es lo que más valor da por hora
invertida y no compromete ninguna decisión posterior.

### 0.1 Completar los metadatos del paquete

`pyproject.toml` no tiene URLs ni descripción larga.

```toml
[project.urls]
Homepage = "https://github.com/Joshua203-byte/Data"
Documentation = "https://github.com/Joshua203-byte/Data/tree/main/vigia/docs"
Issues = "https://github.com/Joshua203-byte/Data/issues"
Changelog = "https://github.com/Joshua203-byte/Data/blob/main/vigia/CHANGELOG.md"
```

Agregar también `"Programming Language :: Python :: 3.13"` a los classifiers, y
verificar que `readme` apunte al README correcto.

**Verificación:** `python -m build` y `twine check dist/*` sin avisos.

### 0.2 CHANGELOG

Formato [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). La v0.1.0
lista los tres módulos, los lectores y las validaciones contra datos reales.

Importa más de lo que parece: es lo primero que mira alguien que evalúa si el
proyecto está vivo.

### 0.3 CI en GitHub Actions

No existe `.github/`. Todo lo que corre, corre en tu máquina.

`.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        python: ["3.11", "3.12", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - run: pip install -e ".[dev,ml]"
      - run: ruff check src tests
      - run: ruff format --check src tests
      - run: mypy src
      - run: pytest -q
```

**Windows en la matriz no es opcional.** El bug del `\r` en los logs de Zeek
—que rompía toda la última columna— solo aparece ahí, y lo encontramos de
casualidad. La restricción cp1252 tiene la misma naturaleza.

### 0.4 Test de codificación cp1252

Hoy la regla vive en la documentación y se verifica a mano. Un test la hace
automática:

```python
def test_todo_el_texto_es_cp1252():
    """La consola de Windows usa cp1252: un carácter fuera de ella hace
    fallar el comando después de haber hecho todo el trabajo."""
    for p in Path("src").rglob("*.py"):
        for i, linea in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            try:
                linea.encode("cp1252")
            except UnicodeEncodeError:
                pytest.fail(f"{p}:{i} tiene caracteres fuera de cp1252")
```

### 0.5 Publicar en PyPI

1. **El nombre `vigia` ya está tomado en PyPI** (verificado el 22/09/2026:
   `pypi.org/pypi/vigia` responde 200). Hay que elegir otro antes de publicar:
   `vigia-nids`, `vigia-dq` o `nids-vigia`. Eso cambia el nombre de instalación
   (`pip install vigia-nids`) pero **no** el del paquete importable ni el del
   comando, que siguen siendo `vigia`.
2. Configurar *trusted publishing* con OIDC — sin tokens en secretos
3. Workflow `release.yml` disparado por tag `v*`
4. `git tag v0.1.0 && git push --tags`

**Verificación:** `pip install vigia` en un entorno limpio, y `vigia audit`
sobre un CSV cualquiera.

---

## Fase 1 — Escala (2-3 días)

**Este es el riesgo técnico real del proyecto.** El benchmark más grande fueron
2,83M filas; nadie sabe qué pasa con 10M.

### 1.1 El problema, medido

`row_hashes` materializa la columna entera a Python:

```python
joined = df.select(pl.concat_str(...)).get_column("_joined").to_list()
return pl.Series("row_hash", [xxhash.xxh64_intdigest(s.encode()) for s in joined])
```

Medido en esta máquina, 8 columnas float:

| Filas | Tiempo | Memoria extra |
|---|---|---|
| 100.000 | 0,1 s | 0,05 GB |
| 1.000.000 | 0,7 s | 0,44 GB |
| 3.000.000 | 2,2 s | 0,89 GB |

**~0,3 GB por millón de filas, lineal.** Con 10M son ~3 GB solo para el hash,
más el DataFrame en memoria. En una máquina de 8 GB, falla.

### 1.2 La corrección

Polars tiene `hash_rows()` nativo, que no pasa por Python. Verificado que existe
y funciona en la versión instalada (Polars 1.44.2):

```python
def row_hashes(df: pl.DataFrame, columns: list[str] | None = None) -> pl.Series:
    cols = columns if columns is not None else df.columns
    if not cols:
        return pl.Series("row_hash", [0] * df.height, dtype=pl.UInt64)
    return df.select(cols).hash_rows()
```

**Cuidado: cambia los valores del hash.** No es un problema —los hashes solo se
comparan entre sí dentro de una misma ejecución— pero hay que verificar que
ningún test los tenga escritos a mano, y que `full_row_hash` y `row_hash` sigan
siendo consistentes entre sí.

Si `hash_rows()` no reproduce la semántica de nulos que necesitamos (el relleno
`\x00` existe para que `("a|b", "c")` y `("a", "b|c")` no colisionen), la
alternativa es procesar por lotes de 500.000 filas y concatenar.

**Verificación:** los tests de `dup.exact` y `dup.cross_split` tienen que seguir
pasando sin cambios. Son los que dependen del hash.

### 1.3 Benchmark de escala

`benchmarks/escala.py`: genera datasets sintéticos de 1M, 5M, 10M y 25M filas,
mide tiempo y pico de memoria de una auditoría completa, y escribe una tabla.

Dos cosas que tiene que reportar:

- **Pico de RSS**, no el promedio: lo que decide si el proceso muere
- **Qué check es el más caro**, para saber dónde optimizar después

### 1.4 CSE-CIC-IDS2018

**Hecho el 30/09/2026:** los 10 CSV procesados (6,9 GB, 16,2 M de filas) se
auditaron sin errores en 49 a 286 s cada uno; el resultado y sus límites están
en `benchmarks/RESULTADOS.md`.

### 1.5 Modo streaming para datasets que no entran en memoria

Polars tiene `scan_parquet` y ejecución lazy. No todos los checks se pueden
expresar así —`labels.noise` necesita entrenar un modelo— pero los de duplicados
y validez sí.

Diseño: un flag `--streaming` que corre solo los checks compatibles y reporta
explícitamente cuáles se saltaron por ese motivo. Mejor que fingir que corrió
todo.

---

## Fase 2 — API REST (4-5 días)

El panel web necesita una API detrás. Hacerla primero permite usarla desde
scripts aunque el panel no exista todavía.

### 2.1 Stack

FastAPI, que ya es la elección estándar y genera OpenAPI solo. Dependencia
opcional:

```toml
api = ["fastapi>=0.110", "uvicorn[standard]>=0.29", "python-multipart>=0.0.9"]
```

### 2.2 Endpoints

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/api/v1/datasets` | Sube un dataset, devuelve un id |
| `POST` | `/api/v1/audits` | Lanza una auditoría, devuelve un id de trabajo |
| `GET` | `/api/v1/audits/{id}` | Estado y resultado |
| `GET` | `/api/v1/audits/{id}/report.html` | El reporte |
| `POST` | `/api/v1/poison` | Módulo 2 |
| `POST` | `/api/v1/drift` | Módulo 3, con referencia |
| `GET` | `/api/v1/checks` | Catálogo |
| `GET` | `/health` | Para el orquestador |

### 2.3 Trabajos asíncronos

**Una auditoría de 2,8M filas tarda 95 segundos.** Eso no entra en una petición
HTTP: hay que devolver un id y consultar el estado.

Para v1, una cola en proceso con `asyncio` y un diccionario de estados alcanza.
Celery y Redis son para cuando haya más de una instancia; agregarlos ahora es
complejidad sin beneficio.

Estados: `pendiente` → `corriendo` → `terminado` | `fallido`.

### 2.4 Seguridad — la parte que no se puede improvisar

Esto recibe archivos de terceros y los procesa. El diseño (sección 12) ya lo
marca, y hay cuatro cosas obligatorias:

1. **Límite de tamaño de subida.** Sin esto, cualquiera agota el disco. 500 MB
   por defecto, configurable.
2. **Validación de extensión y contenido.** No confiar en el nombre del archivo.
3. **Nunca `pickle`.** Está en el diseño y vale repetirlo: un `.pkl` de un
   tercero es ejecución de código arbitrario.
4. **Los PCAP en un contenedor aislado.** Parsear formatos binarios de red es
   históricamente donde aparecen los desbordamientos. *Resuelto por omisión:*
   la API solo acepta CSV y Parquet (un PCAP recibe 415) y la imagen no incluye
   `nfstream`. Si algún día se acepta PCAP en la API, este punto se reabre.

Autenticación por clave de API en la cabecera para v1. OAuth solo si alguien lo
pide.

**Límite de peticiones** en los endpoints que lanzan trabajos: una auditoría
consume CPU y memoria durante minutos.

### 2.5 Tests

Con `TestClient` de FastAPI. Los casos que importan no son los felices:

- Archivo más grande que el límite → 413, no 500
- Extensión no soportada → 415 con la lista de las válidas
- Id de trabajo inexistente → 404
- Dos trabajos simultáneos no se pisan
- El dataset subido se borra al terminar

---

## Fase 3 — Panel web (1-2 semanas)

### 3.1 Qué tiene que responder, en orden

Una persona que abre el panel quiere saber, en este orden:

1. **¿Mi dataset está bien?** → el semáforo, grande, arriba de todo
2. **¿Qué está mal?** → los hallazgos ordenados por severidad
3. **¿Qué hago?** → la recomendación de cada uno y el botón de corregir
4. **¿Cuánto mejoró?** → antes y después

**El semáforo gris es la parte más fácil de arruinar.** "No encontré nada" y
"está limpio" no son lo mismo, y un panel que muestra verde cuando la mitad de
los checks no corrió es peor que no tener panel. El gris tiene que ser tan
visible como el rojo, con la lista de qué no se ejecutó y por qué.

### 3.2 Stack

React con Vite y TypeScript. Sin framework de UI pesado: son cuatro pantallas.

Para los gráficos, uno solo: distribuciones de PSI en deriva y el antes/después
del benchmark. Recharts alcanza.

### 3.3 Pantallas

| Pantalla | Contenido |
|---|---|
| Subir | Arrastrar archivo, elegir columnas, lanzar |
| Resultado | Semáforo, hallazgos expandibles, checks no ejecutados |
| Corregir | Qué correcciones aplican, previsualización, descargar |
| Deriva | Comparar contra una referencia, PSI por columna |

### 3.4 Accesibilidad

**El semáforo no puede ser solo color.** Entre el 5 % y el 8 % de los hombres
tienen daltonismo rojo-verde, y este panel usa exactamente esos dos colores para
la distinción más importante que muestra. Cada estado lleva además un icono y la
palabra.

Contraste mínimo 4.5:1, navegación por teclado, y que el HTML del reporte siga
funcionando sin JavaScript.

### 3.5 Docker

```dockerfile
FROM python:3.12-slim
# ... build del frontend, instalación del paquete, usuario sin privilegios
```

`docker-compose.yml` con la API y un volumen para los datasets. Es lo que hace
que alguien lo pruebe en cinco minutos en vez de en una tarde.

---

## Fase 4 — Deuda técnica (2-3 días)

Cosas que hoy funcionan pero que van a doler después.

### 4.1 El ranking combinado de envenenamiento — ya resuelto

**Esta sección quedó desactualizada al escribir el plan: el fix ya estaba en
el repo** (commit `dad3a17` del historial original, que no se publica, "Normalizar los puntajes de cada detector antes
de combinarlos", anterior a este documento). `combine.py` normaliza cada
detector a su propio rango `[0, 1]` antes de combinar (`_normalizar()`), que
es el camino 1 que esta sección proponía.

Con eso medido contra Engelen, la causa de que el combinado dé 2,5x mientras
`poison.trigger` da 19,2x **no era la normalización**: es que sobre ruido de
etiqueta natural los detectores casi no se solapan (`poison.cluster` no
comparte ni una fila con los otros tres — ver `benchmarks/RESULTADOS.md`,
"La premisa de la coincidencia resultó ser condicional"). Exigir
`min_detectors=2` descarta la mayoría de los aciertos por diseño, no por un
error de escala. Eso es el camino 2 (listas por detector), y también ya está
implementado: `min_detectors=1` en `rank_suspects()`/`--min-detectors 1` en
la CLI, documentado en `docs/ENVENENAMIENTO.md` con la tabla de cuándo usar
cada valor.

No queda trabajo pendiente acá. La documentación es honesta sobre la
limitación: coincidencia entre detectores es señal fuerte para envenenamiento
**inyectado**, no para ruido de etiqueta **natural**.

### 4.2 `poison.cluster` — marcado como experimental

Pesa cero en el puntaje combinado. Se optó por la opción de menor esfuerzo que
esta sección planteaba: marcarlo como experimental en la documentación (el
docstring de `ClusterDetector` en `src/vigia/poison/detectors.py`, además de
`docs/ENVENENAMIENTO.md`, que ya traía toda la evidencia) y dejarlo así.
Cambiarle el criterio (separación del centro de la clase en vez de compacidad)
ya se probó y tampoco discriminaba, así que no hay una segunda opción barata
pendiente.

No es urgente: está documentado y no ensucia el ranking.

### 4.3 Cobertura de tests

188 tests, pero sin medir cobertura. Agregar `pytest-cov` y un umbral en CI
(empezar en el valor actual, subirlo con el tiempo).

Importa más en las rutas de error que en las felices: un check que falla tiene
que ir a `skipped` con el motivo, y eso hoy se prueba poco.

### 4.4 Versionado de la API pública

`vigia.load()`, `vigia.audit()` y el formato del JSON son API pública desde que
alguien lo instale. Documentar qué se considera estable y qué no, y seguir
SemVer de verdad.

---

## Fase 5 — P2 (abierto)

Lo que el diseño marca como posterior. No hace falta para 1.0.

| Qué | Esfuerzo | Nota |
|---|---|---|
| Envenenamiento clean-label | Alto | Es investigación, no implementación |
| Deriva en streaming (ADWIN, DDM) | Medio | Requiere repensar el módulo 3 |
| Kafka | Medio | Solo si alguien lo pide |
| Más lectores (NetFlow, IPFIX) | Bajo | El patrón ya está |
| Perfiles por dataset | Bajo | **Hecho** (R17): los 5 datasets, sin umbrales por dataset todavía |

**Sobre clean-label:** un ataque que usa etiquetas correctas pero elige ejemplos
que mueven la frontera de decisión no deja ninguna de las huellas que buscan los
cuatro detectores actuales. No es un check más: es un método distinto. Si
interesa, conviene tratarlo como una línea de investigación con su propia
validación.

---

## Riesgos

| Riesgo | Probabilidad | Impacto | Qué hacer |
|---|---|---|---|
| Un dataset de 10M+ filas agota la memoria | Baja (mitigado) | Alto | `--streaming`; medido hasta 25M filas sintéticas y 7,9M reales |
| El nombre `vigia` está tomado en PyPI | **Confirmado** | Bajo | Publicar como `vigia-nids`; el comando sigue siendo `vigia` |
| El panel muestra verde cuando hay checks saltados | Media | **Alto** | El gris tan visible como el rojo |
| NFStream no compila en alguna plataforma | Media | Bajo | Ya es opcional, el error lo explica |
| El ranking combinado no mejora | Media | Medio | Plan B: listas por detector |
| Alguien sube un PCAP malicioso | Baja | **Alto** | La API no acepta PCAP; reabrir si eso cambia |
| Varias auditorías simultáneas agotan la memoria de la API | Media | **Alto** | **Mitigado:** `VIGIA_MAX_CONCURRENT_JOBS` (1 por defecto) con una cola chica y `503` cuando se llena; el contenedor de producción tiene un tope de 6 GB. Un solo trabajo grande sigue picando a 5 GiB |

---

## Orden recomendado

```
Semana 1   Fase 0 (medio día)  +  Fase 1 (escala)
           └─ termina con: instalable desde PyPI, CI en verde,
              y un número real de hasta dónde aguanta

Semana 2   Fase 2 (API REST)
           └─ termina con: API documentada y usable desde scripts

Semana 3-4 Fase 3 (panel web)
           └─ termina con: docker compose up y funciona

Después    Fase 4 (deuda) y Fase 5 (P2), sin apuro
```

**Por qué la escala antes que la API.** Si resulta que Vigía no aguanta 10M
filas, eso cambia el diseño de la API —hace falta streaming, trabajos más
largos, límites distintos— y rehacerla después cuesta más que medirlo ahora.

**Por qué el empaquetado primero.** Medio día que da algo compartible de
inmediato y no compromete ninguna decisión posterior. Si el proyecto se detiene
por cualquier motivo, al menos queda instalable.
