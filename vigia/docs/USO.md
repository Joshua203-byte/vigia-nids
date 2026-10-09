# Guía de uso

Referencia completa de la línea de comandos y del SDK de Python.

**Índice:** [Línea de comandos](#línea-de-comandos) · [API REST](#api-rest) ·
[Panel web](#panel-web) · [SDK](#sdk) ·
[Formato del reporte JSON](#formato-del-reporte-json) ·
[Formatos de entrada](#formatos-de-entrada) ·
[Recetas](#recetas) · [Integración con CI](#integración-con-ci)

---

## Línea de comandos

### `vigia audit`

Audita un dataset y reporta los hallazgos.

```bash
vigia audit <archivo-o-carpeta> [opciones]
```

| Opción | Qué hace |
|---|---|
| `--label-col` | Columna de etiqueta |
| `--split-col` | Columna de partición (train/test) |
| `--time-col` | Columna de marca de tiempo |
| `--src-ip-col` / `--dst-ip-col` | Columnas de IP |
| `--time-format F` | Formato de la columna de tiempo (`'%m/%d/%Y %H:%M:%S'`). Hace falta cuando día y mes son ambiguos: sin él, `leak.temporal` se salta y lo dice. También en `vigia fix` |
| `--profile NOMBRE` | Perfil de un dataset conocido (`cic-ids-2017`, `cse-cic-ids-2018`, `unsw-nb15`, `unsw-nb15-raw`, `ugr-16`, `ctu-13`); un `--*-col` explícito gana sobre el perfil |
| `--event-type` | Solo para EVE de Suricata: qué tipo de evento auditar (`flow` por defecto) |
| `--checks` | `all`, ids o categorías separadas por coma |
| `--report DIR` | Escribe `report.html` y `report.json` |
| `--seed N` | Semilla, para reproducibilidad (por defecto 42) |
| `--shortcut-threshold F` | Umbral de exactitud para marcar un atajo (0,95) |
| `--fail-on SEV` | Sale con código 1 si hay hallazgos de esa severidad o peor |
| `--streaming` | Para datasets que no entran en memoria (ver abajo) |

Las columnas que no se indican se detectan por nombre. Si no se encuentran, los
checks que dependen de ellas se saltan y lo dicen.

**Columnas declaradas.** El tiempo y las IPs que se pasan con `--time-col`,
`--src-ip-col`, `--dst-ip-col` o con un perfil se tratan como metadatos:
`shortcut.identifier` no las marca y quedan fuera del hash con el que se
decide si dos filas son duplicadas (`dup.exact`, `dup.cross_split`, `dup.near`,
`labels.conflict` y `drop_duplicates`). Así, el mismo flujo visto desde otra IP
u otra hora cuenta como duplicado. Siguen disponibles para
`shortcut.single_feature` y los checks de fuga. Una columna solo detectada por
nombre no cuenta como declarada: se sigue marcando como identificador.

**Modo streaming.** Con `--streaming`, Vigía no carga el archivo entero en
memoria: lee un CSV o Parquet con ejecución perezosa de Polars y calcula por
agregación lo que hace falta. Solo corren los checks de duplicados
(`dup.exact`, `dup.cross_split`, que también excluyen las columnas declaradas)
y de validez (`validity.nan_inf`, `validity.constant`) — el resto (fuga, atajos, ruido de etiqueta…) necesita el
dataset completo en memoria para funcionar, y quedan listados en "checks no
ejecutados" con el motivo, igual que cualquier otro check saltado. No soporta
carpetas ni los formatos que ya construyen el dataset completo al leerlo
(Zeek, Suricata, PCAP).

Detecta la etiqueta y el split por nombre y quita los espacios de los nombres de
columna igual que el modo normal, así que `--label-col Label` sirve sobre un CSV
de CICFlowMeter (`" Label"`). Si un check de duplicados no puede correr (sin
columna de split, un solo valor de split), queda en "checks no ejecutados" con el
mismo motivo que en el modo normal. En `validity.nan_inf` reporta cada columna
por separado, sin agrupar las que comparten el mismo recuento.

```bash
vigia audit data/flows_grande.parquet --streaming --label-col Label
```

**Códigos de salida:**

| Código | Significa |
|---|---|
| 0 | Terminó bien |
| 1 | Hay hallazgos que alcanzan el umbral de `--fail-on` |
| 2 | Error de uso: archivo ilegible, opción inválida, columna inexistente |
| 3 | Error interno: un check falló o hubo un error inesperado. El reporte está incompleto |

La distinción importa en CI: un dataset con problemas (1) no es lo mismo que un
comando mal escrito (2) ni que un bug de Vigía (3). Si hay a la vez hallazgos
que alcanzan `--fail-on` y un check que falló, sale 1: ese ya rompe el build.
Con `VIGIA_DEBUG=1` un error inesperado deja pasar el traceback original en
vez de salir con 3.

### `vigia fix`

Aplica correcciones y escribe el dataset corregido. **El original nunca se
toca.**

```bash
vigia fix data/flows.csv \
  --apply drop_duplicates,drop_constant,drop_identifiers \
  --out data/flows_corregido.parquet
```

Las correcciones se aplican en cadena, cada una sobre el resultado de la
anterior, con las mismas columnas declaradas (`--time-col`, `--src-ip-col`,
`--dst-ip-col`, `--profile`): usá las mismas opciones que en `vigia audit`, o
`drop_duplicates` deduplicará con otra clave que la que usó la auditoría. Una
que no aplica se informa y se sigue con las demás. `--out` no puede ser el
archivo de entrada (sale con código 2).

Si alguna aparta filas (`quarantine_noise`), se escriben en
`<nombre>_cuarentena.<ext>` junto al archivo de salida.

**Parquet conserva los tipos; CSV no.** Para encadenar auditorías conviene
Parquet.

### `vigia poison`

Busca registros insertados a propósito. Detalle en
[`ENVENENAMIENTO.md`](ENVENENAMIENTO.md).

```bash
vigia poison data/flows.parquet --top 20 --min-detectors 2
```

| Opción | Qué hace |
|---|---|
| `--label-col` | Columna de etiqueta |
| `--top N` | Cuántas filas sospechosas listar (20) |
| `--min-detectors N` | Solo las señaladas por N detectores o más (2) |
| `--report DIR` | Escribe los reportes |

`--min-detectors 2` es el valor por defecto porque la coincidencia entre
métodos independientes es lo que separa lo revisable del ruido. Con `1` se ven
todos los hallazgos individuales.

### `vigia drift`

Compara un lote nuevo contra la referencia. Detalle en [`DERIVA.md`](DERIVA.md).

```bash
vigia drift lote_de_hoy.parquet --reference datos_entrenamiento.parquet
```

| Opción | Qué hace |
|---|---|
| `--reference PATH` | **Obligatoria.** El dataset con el que se entrenó |
| `--psi-threshold F` | PSI a partir del cual reportar una columna (0,2) |
| `--fail-on SEV` | Sale con código 1 si hay deriva de ese nivel o peor |
| `--report DIR` | Escribe los reportes |

### `vigia checks` y `vigia fixes`

Listan lo disponible. `vigia checks --module all` muestra los checks de los tres
módulos; sin la opción, solo los del auditor.

### `vigia version`

Muestra la versión instalada.

### `vigia serve`

Levanta la API REST (ver [abajo](#api-rest)). Requiere el extra `api`:
`pip install 'vigia-nids[api]'`.

```bash
vigia serve --host 0.0.0.0 --port 8000 --reload
```

---

## API REST

El panel web (fase 3 de `docs/PLAN.md`) necesita una API detrás, y sirve por su
cuenta desde scripts aunque el panel no exista. Requiere el extra `api`:

```bash
pip install 'vigia-nids[api]'
vigia serve --port 8000
# o, sin pasar por la CLI:
uvicorn vigia.api.app:app --port 8000
```

### Autenticación

Clave de API en la cabecera `X-API-Key`, comparada contra la variable de
entorno `VIGIA_API_KEY`.

**Sin `VIGIA_API_KEY` seteada, la API corre sin autenticación** (para no
tener fricción en desarrollo local), pero al arrancar se loguea un warning
explícito. **Con `VIGIA_ENV=production` el arranque falla si falta la clave**
(o si `VIGIA_CORS_ORIGINS` contiene `*`): el compose de producción lo setea,
así la imagen nunca queda abierta en silencio. Si se expone la API fuera de
una máquina de desarrollo, hay que setear la variable:

```bash
export VIGIA_API_KEY="una-clave-larga-y-al-azar"
vigia serve
```

Con la variable seteada, cualquier pedido sin la cabecera correcta responde
`401`.

### Límites y seguridad

Todas las variables se leen y validan juntas al arrancar: un valor inválido
(negativo, no numérico) aborta el servidor con un mensaje que nombra la
variable, en vez de fallar en la primera petición.

| Variable | Qué limita | Por defecto |
|---|---|---|
| `VIGIA_MAX_UPLOAD_MB` | Tamaño de una subida | 200 |
| `VIGIA_RATE_LIMIT_PER_MINUTE` | Peticiones por minuto y por IP, sobre la subida y `/audits`, `/poison` y `/drift` | 30 |
| `VIGIA_MAX_CONCURRENT_JOBS` | Trabajos que corren a la vez | 1 |
| `VIGIA_MAX_QUEUED_JOBS` | Trabajos que esperan turno (`pendiente`) | 4 |
| `VIGIA_UPLOAD_TTL_MINUTES` | Minutos que una subida sin trabajo espera antes de borrarse | 30 |
| `VIGIA_REPORT_TTL_MINUTES` | Minutos que se guarda un trabajo terminado o fallido | 60 |
| `VIGIA_MAX_STORED_JOBS` | Trabajos guardados en memoria | 200 |
| `VIGIA_STORAGE_QUOTA_MB` | Total del directorio de subidas | 2048 |
| `VIGIA_MAX_ROWS` | Filas de un dataset subido | 5.000.000 |
| `VIGIA_MAX_EXPANDED_MB` | Memoria estimada de un dataset (filas × columnas × 8 bytes). El pico de una auditoría es ~8× eso; al arrancar se avisa si el valor × 8 supera la memoria del contenedor | 700 |
| `VIGIA_ENV` | `development` o `production` (ver Autenticación) | `development` |
| `VIGIA_CORS_ORIGINS` | Orígenes permitidos, separados por coma; sin `*` | los de desarrollo |

Códigos de error de estos límites:

| Código | Cuándo |
|---|---|
| `401` | Clave de API ausente o incorrecta |
| `404` | `dataset_id` o `job_id` que nunca existió (o ya se borró el dataset) |
| `410` | El trabajo **caducó**: el reporte se guardó `VIGIA_REPORT_TTL_MINUTES` y se borró. Hay que volver a lanzarlo |
| `413` | Subida o cuerpo por encima del límite, o dataset con demasiadas filas |
| `415` | Extensión no soportada o contenido ilegible |
| `422` | `dataset_id` o `job_id` con una forma que la API no genera |
| `429` | Más de `VIGIA_RATE_LIMIT_PER_MINUTE` peticiones por minuto desde la misma IP |
| `503` | La cola de trabajos está llena: reintentar tras el `Retry-After`. El dataset no se gasta |
| `507` | La subida haría pasar el directorio de subidas de `VIGIA_STORAGE_QUOTA_MB` |

**Un dataset por trabajo.** Cada trabajo borra sus datasets al terminar
(`terminado` o `fallido`): para volver a auditar el mismo archivo hay que
subirlo otra vez. Una subida que ningún trabajo reclama se borra a los
`VIGIA_UPLOAD_TTL_MINUTES`; una que ya espera en la cola **no** caduca. Al
arrancar, el servidor borra los directorios `vigia_api_*` que dejó una
ejecución anterior, salvo los de un proceso vivo (con dos procesos sobre el
mismo `TMPDIR` no se pisan, pero `--workers` mayor a 1 sigue sin estar
soportado).

**Cuerpos y subidas.** Un middleware corta el cuerpo en la red: rechaza por el
`Content-Length` declarado sin leer nada y, sin `Content-Length`
(`Transfer-Encoding: chunked`), cuenta los bytes que llegan y corta al pasarse.
En producción el límite también va en el proxy (`request_body { max_size }` en
Caddy). Los cuerpos JSON de las demás rutas tienen un tope de 64 KiB.

**Validación.** Un Parquet se mira por su pie (esquema y número de filas) sin
descomprimirlo, y un CSV se lee en una muestra de 10.000 filas con el mismo
lector que la auditoría (acepta Windows-1252, como la CLI); las filas se cuentan
sin cargar el archivo. Corre en un hilo, así que `/health` responde mientras
tanto.

**Errores.** Al cliente le llega un mensaje genérico y un id de correlación
(`id: 3fa9c2b01d4e`); el mensaje original y el traceback quedan en el log del
servidor con ese id. Lo mismo vale para los checks que fallan en el reporte
(`errors`): se ve el tipo de la excepción y el id.

**Formatos.** Solo `.csv`, `.parquet` y `.pq`: Zeek, Suricata y PCAP quedan fuera
de la API (ya los cubre la CLI).

### Endpoints

| Método | Ruta | Qué hace |
|---|---|---|
| `GET` | `/health` | 200 simple, sin autenticación, para el orquestador |
| `POST` | `/api/v1/datasets` | Sube un dataset (`multipart/form-data`, campo `file`). Devuelve `dataset_id` |
| `POST` | `/api/v1/audits` | Lanza una auditoría sobre un `dataset_id`. Devuelve `job_id` |
| `GET` | `/api/v1/audits/{job_id}` | Estado del trabajo (`pendiente`/`corriendo`/`terminado`/`fallido`) y el resultado si terminó |
| `GET` | `/api/v1/audits/{job_id}/report.html` | El reporte HTML, una vez `terminado` |
| `POST` | `/api/v1/poison` | Lanza el módulo de envenenamiento sobre un `dataset_id`. Devuelve `job_id` |
| `GET` | `/api/v1/poison/{job_id}` | Estado y resultado, igual que `/audits/{job_id}` |
| `POST` | `/api/v1/drift` | Lanza el módulo de deriva: `dataset_id` (lote) + `reference_id` (referencia, otro dataset subido). Devuelve `job_id` |
| `GET` | `/api/v1/drift/{job_id}` | Estado y resultado |
| `GET` | `/api/v1/checks` | Catálogo de checks de los tres módulos |

Todos los endpoints bajo `/api/v1` exigen `X-API-Key` cuando `VIGIA_API_KEY`
está seteada. Un `job_id` o `dataset_id` desconocido responde `404` (un trabajo
caducado, `410`); uno con otra forma que los 32 caracteres hexadecimales que
genera la API responde `422`. El panel se sirve desde `/` con fallback de
aplicación de una sola página: `/resultado/<id>` devuelve el panel, `/api/...`
y `/health` mantienen sus propios `404`.

La petición de `/audits` acepta `label_col`, `split_col`, `time_col`,
`src_ip_col`, `dst_ip_col`, `time_format` (ver `--time-format`), `checks` y
`seed`. El resultado de los tres tipos de trabajo es el JSON de
[Formato del reporte JSON](#formato-del-reporte-json), con `errors` y
`schema_version`.

**Memoria.** Una auditoría carga el dataset entero en el proceso. Medido el
04/10/2026 con `Friday-02-03-2018` de CSE-CIC-IDS2018 (1.048.575 filas, 80
columnas, `--profile cse-cic-ids-2018`, todos los checks del auditor), el pico
fue de 5,4 GiB y tardó 157 s en una máquina de 28 núcleos. Por eso la API corre
**un trabajo a la vez** por defecto (`VIGIA_MAX_CONCURRENT_JOBS`); los demás
esperan en una cola de `VIGIA_MAX_QUEUED_JOBS` y, llena, responden `503`.
Subir el tope solo tiene sentido con memoria de sobra: los picos se suman.

**Los trabajos son asíncronos.** Una auditoría de 2,8M filas tarda 95
segundos, así que `/audits`, `/poison` y `/drift` devuelven de inmediato un
`job_id` (`202 Accepted`) y hay que consultar el estado por separado. Es una
cola en proceso, sin Celery ni Redis: un diccionario en memoria alcanza para
una sola instancia. Eso también significa que los trabajos no sobreviven un
reinicio del servidor, y que los terminados caducan (`VIGIA_REPORT_TTL_MINUTES`).

### Ejemplo con curl

```bash
# Subir un dataset
curl -X POST http://localhost:8000/api/v1/datasets \
  -H "X-API-Key: $VIGIA_API_KEY" \
  -F "file=@flows.csv"
# {"dataset_id": "a1b2c3...", "n_rows": 2830743, "n_cols": 79}

# Lanzar la auditoría
curl -X POST http://localhost:8000/api/v1/audits \
  -H "X-API-Key: $VIGIA_API_KEY" -H "Content-Type: application/json" \
  -d '{"dataset_id": "a1b2c3...", "label_col": "Label", "split_col": "split"}'
# {"job_id": "d4e5f6..."}

# Consultar el estado hasta que termine
curl http://localhost:8000/api/v1/audits/d4e5f6... -H "X-API-Key: $VIGIA_API_KEY"

# Una vez "terminado", el reporte HTML
curl http://localhost:8000/api/v1/audits/d4e5f6.../report.html \
  -H "X-API-Key: $VIGIA_API_KEY" -o reporte.html
```

---

## Panel web

React + Vite + TypeScript, en `web/`. Cuatro pantallas: Subir, Resultado,
Corregir y Deriva, siguiendo el orden de la sección anterior: primero el
semáforo, después qué está mal, después qué hacer.

**El semáforo gris nunca es "está limpio".** Un dataset con cero hallazgos
pero con checks saltados se muestra en gris, con la lista de qué no corrió y
por qué, tan visible como si fuera rojo — nunca escondida detrás de un
desplegable.

**Desarrollo:**

```bash
cd web
npm install
npm run dev          # http://localhost:5173, apunta a la API en :8000
```

Necesita la API corriendo aparte (`vigia serve` o `uvicorn vigia.api.app:app`)
con CORS habilitado para `http://localhost:5173`, que es el valor por
defecto de `VIGIA_CORS_ORIGINS`.

**Producción:** `docker compose up --build` desde la raíz del repo construye
el panel, lo sirve como estático desde el mismo proceso de FastAPI (sin
nginx aparte) y deja todo navegable en `http://localhost:8000`.

**Limitación conocida:** la pantalla "Corregir" solo *sugiere* qué
correcciones aplican (según el campo `auto_fix` de cada hallazgo) y arma el
comando de `vigia fix` correspondiente. La API todavía no tiene un endpoint
para aplicarlas; eso sigue siendo trabajo de la CLI.

---

## SDK

### Auditar

```python
import vigia

ctx = vigia.load(
    "data/flows.parquet",
    label_col="Label",  # opcional: se detecta solo
    split_col="split",
)
report = vigia.audit(ctx)

print(report.traffic_light())  # 'rojo' | 'amarillo' | 'verde' | 'gris'
print(report.counts())  # {'critical': 2, 'high': 1, ...}

for f in report.sorted_findings():
    print(f.severity, f.check_id, f.title)

for check_id, motivo in report.skipped.items():
    print(f"no corrió: {check_id} — {motivo}")
```

`vigia.load()` acepta `label_col`, `split_col`, `time_col`, `src_ip_col`,
`dst_ip_col`, `src_port_col`, `dst_port_col`, `protocol_col`, `profile`,
`time_format`, `event_type`, `strip_names`, `seed`, y cualquier opción extra como configuración
(`shortcut_threshold`, `near_duplicate_threshold`, `noise_min_ratio`,
`min_class_examples`, `train_ratio`, `group_by`, `psi_threshold`). Las columnas de
tiempo e IP pasadas explícitamente (o por perfil) quedan en
`ctx.declared_roles`.

### Corregir

```python
from vigia.fixes import apply_fix, available_fixes
from vigia.fixes.base import FixNotApplicable

try:
    r = apply_fix(ctx, "drop_duplicates")
    print(r.summary)  # "2.633 filas duplicadas eliminadas..."
    print(r.rows_before, "->", r.rows_after)
    df_corregido = r.df
    if r.quarantined is not None:
        r.quarantined.write_parquet("revisar.parquet")
except FixNotApplicable as e:
    print("no aplica:", e)
```

### Medir cuánto del rendimiento era real

```python
from vigia.benchmark import compare, evaluate

m = evaluate(ctx)
print(m.f1_macro, m.per_class_recall, m.fp_per_10k_benign)

c = compare(ctx, ["drop_identifiers"])
print(c.summary())  # "F1 macro: 0.9999 -> 0.8712 (-0.1287)"
```

Una caída **no** significa que las correcciones empeoraron el modelo: significa
que el número original estaba inflado por los defectos que se acaban de quitar.

Requiere `pip install 'vigia-nids[ml]'`.

### Buscar envenenamiento

```python
from vigia.core.engine import run_audit
from vigia.poison import rank_suspects

report = run_audit(ctx, module="poison")
for s in rank_suspects(report.findings, top=50, min_detectors=2):
    print(s.row, f"{s.score:.3f}", s.detectors)
```

Y para medir si los detectores funcionan sobre tus datos:

```python
from vigia.poison import inject_label_flip

spec = inject_label_flip(df, "Label", ratio=0.02, seed=42)
# ...correr los detectores sobre spec.df...
print(spec.evaluate(filas_detectadas))  # precisión, recall, F1
```

### Medir deriva

```python
from vigia.core.engine import run_audit
from vigia.io.readers import read_dataset

ctx = vigia.load("lote_nuevo.parquet", label_col="Label")
ctx.reference = read_dataset("referencia.parquet")

report = run_audit(ctx, module="drift")
if report.exceeds("high"):
    print("hay que reentrenar")
```

Las métricas también se usan sueltas:

```python
from vigia.drift.metrics import psi, ks_statistic, js_divergence

psi(referencia["bytes_fwd"], actual["bytes_fwd"])  # > 0,25 -> reentrenar
```

### Contexto a mano

Para datasets que ya están en memoria:

```python
import polars as pl
from vigia.core.context import AuditContext
from vigia.core.engine import run_audit

ctx = AuditContext(
    df=mi_dataframe,
    label_col="Label",
    split_col="split",
    seed=42,
)
report = run_audit(ctx)
```

---

## Formato del reporte JSON

```json
{
  "schema_version": "1",
  "dataset": {"path": "...", "sha256": "...", "n_rows": 2830743, "n_cols": 80},
  "run": {"vigia_version": "1.0.0", "seed": 42},
  "summary": {
    "traffic_light": "rojo",
    "counts": {"critical": 1, "high": 6, "medium": 1, "low": 3, "info": 0},
    "total": 11,
    "n_skipped": 3,
    "n_errors": 0
  },
  "findings": [
    {
      "check_id": "dup.cross_split",
      "severity": "critical",
      "title": "288.790 filas aparecen en más de un split",
      "description": "...",
      "metric": {"ratio": 0.0926, "n_rows_affected": 288790.0},
      "affected_rows": 288790,
      "examples": [{"...": "..."}],
      "recommendation": "...",
      "auto_fix": "drop_duplicates"
    }
  ],
  "skipped": {"leak.temporal": "requiere 'time_col' (no fue especificado ni detectado)"},
  "errors": {}
}
```

Los hallazgos vienen ordenados de más grave a menos grave. `sha256` identifica
el archivo exacto que se auditó. `schema_version` identifica el formato de este
JSON: solo sube con un cambio incompatible.

**`n_skipped` importa tanto como `counts`.** Un reporte con cero hallazgos y
tres checks saltados no dice que el dataset esté limpio.

**`errors` no es lo mismo que `skipped`.** Un check saltado no aplicaba a este
dataset (falta una columna, una dependencia). Uno en `errors` falló por un bug
de Vigía (`"TypeError: ..."`) y no dice nada del dataset: con `n_errors > 0` el
semáforo es rojo y la CLI sale con código 3.

---

## Formatos de entrada

| Formato | Extensión | Qué hay que saber |
|---|---|---|
| CSV | `.csv`, `.txt` | Reintenta en cp1252 si no es UTF-8 |
| Parquet | `.parquet`, `.pq` | Conserva los tipos; el mejor para encadenar |
| Zeek | `.log` | TSV con cabecera o JSON Lines, se detecta solo |
| Suricata EVE | `.json`, `.eve` | Ver `--event-type` abajo |
| PCAP | `.pcap`, `.pcapng`, `.cap` | Requiere `pip install 'vigia-nids[pcap]'` |

Una carpeta se lee entera y se concatena, salvo los PCAP: extraer flujos tarda
minutos por archivo, así que hay que nombrar uno.

### Zeek

```bash
vigia audit /opt/zeek/logs/2026-09-19/conn.log
```

Los nulos de Zeek (`-` y `(empty)`) se convierten a nulo de verdad, y los tipos
declarados en `#types` se respetan. Las columnas `id.orig_h`, `id.resp_p` y
compañía se reconocen solas.

**Un `conn.log` no trae etiquetas**, así que los checks de etiquetas y de split
se saltan y el semáforo da gris. Es correcto: no hay nada que auditar ahí hasta
que se etiquete.

### Suricata EVE

Un `eve.json` mezcla alertas, flujos y transacciones HTTP y DNS en el mismo
archivo. **Por defecto se leen los flujos**, pero las alertas son las que traen
algo parecido a una etiqueta:

```bash
vigia audit eve.json                      # flujos
vigia audit eve.json --event-type alert   # alertas, con alert_signature de etiqueta
```

Los objetos anidados se aplanan: `alert.signature` pasa a `alert_signature`.

Pedir un tipo que no está en el archivo lista los que sí hay.

### PCAP

```bash
pip install 'vigia-nids[pcap]'     # en Linux hace falta además libpcap-dev
vigia audit captura.pcapng
```

Los flujos se extraen con **NFStream, no con CICFlowMeter**. Los defectos
documentados de los datasets CIC —duraciones negativas, división por cero en
las tasas, el centinela `-1` en las ventanas TCP— vienen de CICFlowMeter, y
usar la misma herramienta reproduciría exactamente los artefactos que Vigía
existe para detectar.

**Las columnas no son las de CIC-IDS2017.** NFStream calcula su propio conjunto
de métricas, así que un modelo entrenado con features de CICFlowMeter no se
evalúa directamente sobre estos flujos. Lo que sí permite es auditar la calidad
de una captura propia.

---

## Recetas

### Los datasets CIC vienen partidos por día

```bash
vigia audit data/MachineLearningCVE/    # carpeta entera
```

Se concatenan y se agrega `__source_file` para conservar la procedencia. Esa
columna **no** entra en el hash de duplicados, igual que las columnas de tiempo
e IP declaradas: si entraran, dos flujos idénticos capturados en días distintos
o desde otro host dejarían de contarse como duplicados, que es justamente lo que
hay que ver.

### El dataset no trae columna de split

Es el caso de CIC-IDS2017. Hay que crearla, y ahí está la decisión que más
cambia los resultados:

```python
import polars as pl

# Al azar: lo que hace casi toda la literatura
d = df.sample(fraction=1.0, shuffle=True, seed=42)
n = int(d.height * 0.7)
d = d.with_columns(
    pl.when(pl.int_range(pl.len()) < n)
    .then(pl.lit("train"))
    .otherwise(pl.lit("test"))
    .alias("split")
)

# Por corte temporal: lo que hace un NIDS en producción
from vigia.fixes import apply_fix

d = apply_fix(ctx, "temporal_split").df
```

Sobre CIC-IDS2017, esa diferencia lleva el recall de DoS Hulk, PortScan y DDoS
de un valor que con el split aleatorio oscila entre 0 y casi 1 según la semilla
a **0,00 en las 10 semillas** (ver `benchmarks/RESULTADOS.md`).

### Auditar, corregir y volver a auditar

```bash
vigia audit data/flows.csv --report out/antes/
vigia fix data/flows.csv --apply drop_duplicates,drop_constant --out data/limpio.parquet
vigia audit data/limpio.parquet --report out/despues/
```

### Solo una familia de checks

```bash
vigia audit data/flows.csv --checks leak        # leak.*
vigia audit data/flows.csv --checks leak,dup.cross_split
```

---

## Integración con CI

```yaml
- name: Auditar el dataset
  run: |
    pip install vigia-nids
    vigia audit data/train.parquet --fail-on critical --report audit/
```

Falla el build si hay hallazgos críticos. Los reportes quedan como artefacto.

Para que sea realmente útil conviene indicar las columnas a mano: si la
detección automática no las encuentra, los checks graves se saltan y el build
pasa sin haber revisado lo que importa. Declarar además las IPs evita que
`shortcut.identifier` marque como defecto columnas que solo sirven para los
checks de fuga.

```bash
vigia audit data/train.parquet \
  --label-col Label --split-col split --time-col Timestamp \
  --src-ip-col "Src IP" --dst-ip-col "Dst IP" \
  --fail-on critical
```
