# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y este proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [Unreleased]

## [1.0.3] - 2026-10-09

El código de los checks no cambia. Cambia dónde vive el proyecto.

### Cambiado

- **El repositorio pasa a `github.com/Joshua203-byte/vigia-nids`.** Todas las URLs
  (paquete, documentación, plantillas, imagen de Docker) apuntan ahí. El historial
  de commits anterior no se publica: el repositorio parte de un solo commit, así que
  los hashes que citan RESULTADOS, PLAN y los reportes de `auditoria-1.0/` son del
  historial original y no se pueden consultar.

### Añadido

- `docs/REPRODUCIR.md`: de dónde sale cada dataset, la estructura de carpetas, los
  recursos que hacen falta y un comando por resultado de RESULTADOS.md.

## [1.0.2] - 2026-10-09

El código de los checks no cambia. Actualiza la página de PyPI con las cifras
nuevas de CIC-IDS2017 y agrega el script que las produce.

### Añadido

- `benchmarks/cic_semillas.py`: repite los escenarios A, B y C de R9 con varias
  semillas y resume la dispersión. En RESULTADOS.md, con 10 semillas, los rangos
  de A y B se solapan (no se puede concluir cuánto inflaban las columnas
  identificadoras) y el recall 0,00 de C se sostiene en las 10.

### Cambiado

- Documentación: RESULTADOS, README y USO dejan de citar "de entre 0,36 y 0,88
  a 0,00" y describen la dispersión; se cita el artículo de CIC-IDS2017
  (Sharafaldin, Lashkari y Ghorbani, ICISSP 2018); PLAN.md refleja que la 1.0
  ya está publicada.

### Eliminado

- Cuatro constantes que nadie leía (`LabelNoiseCheck.MASK_NAME`, `PSI_LEVE`,
  `EVENT_TYPES_UTILES`, `ZEEK_NULLS`) y, del panel web, el README de la
  plantilla de Vite y `icons.svg`, que nada referenciaba.

## [1.0.1] - 2026-10-08

Solo documentación y metadatos; el código no cambia. Existe para que la página de
PyPI muestre el README actual (con enlaces absolutos, cifras corregidas y la
sección de cómo contribuir y reportar una vulnerabilidad) y las URLs del
repositorio renombrado a `Joshua203-byte/vigia-nids`.

## [1.0.0] - 2026-10-06

Primera versión estable. Además de lo que sigue, incluye las correcciones de
la auditoría previa a la publicación: el reporte y su verificación están en
`AUDITORIA-1.0.md` y `VERIFICACION-1.0.md`, en la carpeta `auditoria-1.0/` del repositorio.

### Cambiado

- **API: el límite de subida por defecto baja de 500 a 200 MB**
  (`VIGIA_MAX_UPLOAD_MB`), y la API corre **un trabajo a la vez** por defecto
  (`VIGIA_MAX_CONCURRENT_JOBS`): los demás esperan en una cola de 4 y, llena,
  responden `503` con `Retry-After`. Los trabajos terminados caducan a los 60
  minutos (`410`). Quien dependía de más de un trabajo simultáneo o de subidas de
  entre 200 y 500 MB tiene que subir esas variables.
- **API: `VIGIA_MAX_EXPANDED_MB` vale 700 por defecto** (memoria estimada de un
  dataset, filas × columnas × 8 bytes): el pico de una auditoría es ~8 veces eso, así
  que admite 1 M de filas × 80 columnas. Al arrancar se avisa en el log si el valor × 8
  no entra en la memoria del contenedor.
- **API: `VIGIA_ENV=production` hace fallar el arranque sin `VIGIA_API_KEY`**, y
  `VIGIA_CORS_ORIGINS` con `*` falla siempre; CORS ya no permite credenciales.
  Sin `VIGIA_ENV` el comportamiento es el de antes (abierto, con un warning).
- **API: los errores internos llegan al cliente como un mensaje genérico con un
  id de correlación**, no con el texto de la excepción; el detalle queda en el
  log. Lo mismo para `errors` en el reporte que sale por la API.
- **API: el limitador de peticiones cuenta por IP**, ya no por el valor de
  `X-API-Key`, y la subida (`POST /datasets`) también pasa por él.
- **Docker: imágenes base fijadas por digest**, sin `curl` (el healthcheck usa
  Python), panel de solo lectura y uvicorn con `--proxy-headers`.
- **`vigia fix` sale con 2 (no con 1)** cuando ninguna corrección se pudo aplicar.
- CI: permisos de solo lectura, actions fijadas por SHA, un job del panel y más
  pruebas de la imagen (413, enlace profundo, producción sin clave).
- **`drift.concept` ahora mide la relación con la etiqueta; la validación
  adversaria que tenía ese id se llama `drift.covariate`.** El id cambia en el
  JSON y en `--checks`: quien filtraba por `drift.concept` esperando el AUC tiene
  que pasar a `drift.covariate`. El nuevo `drift.concept` entrena un modelo con la
  referencia y compara, clase por clase, su recall dentro de ella (validación
  cruzada con las filas repetidas juntas) contra su recall en el lote: alta desde
  0,10 de caída del recall medio, crítica desde 0,25, y solo si la caída supera el
  ruido de muestreo. Un lote de una sola clase se puede evaluar; las filas del lote
  que ya estaban en la referencia se excluyen; sin etiqueta en el lote se salta y
  lo dice.
  El módulo de deriva pasa de 4 a 5 checks (25 en total).
- **El JSON del reporte agrega `schema_version` (`"1"`), `errors` y
  `summary.n_errors`.** No se quitó ni renombró nada. Los checks que fallan por un
  bug van a `errors`, ya no a `skipped` con el prefijo "error interno".
- **El semáforo es rojo si algún check falló por un error interno** (antes, sin
  otros hallazgos, salía gris).
- **Códigos de salida de la CLI: se agrega el 3** (un check falló o hubo un error
  inesperado). El 1 sigue siendo "hay hallazgos que alcanzan `--fail-on`", y gana
  si ocurren los dos. Un `--label-col` inexistente sale con 2, no con 1.
- `vigia.__version__` sale de los metadatos del paquete instalado; ya no hay una
  copia escrita a mano (y `release.yml` verifica que el tag coincida).
- Classifier de PyPI: `Development Status :: 4 - Beta` (era Alpha).
- Un id de dataset o de trabajo con otra forma que los 32 caracteres
  hexadecimales de la API responde `422` (antes `404`, o peor, ver Corregido).
- `labels.noise` exige que el modelo elimine al menos el 25 % del error de la
  regla "predecir la mayoritaria" (margen relativo, no 5 puntos).
- En `vigia.benchmark.compare`, `quarantine_noise` se aplica solo al entrenamiento y
  `Comparison` expone `test_changed`: el resultado de ese caso cambia.
- Los `Infinity`, `-Infinity` y `NaN` de un CSV se leen como valores reales, no
  como nulos: `validity.nan_inf` los cuenta como infinitos.
- **Columnas de rol declaradas** (`--time-col`, `--src-ip-col`, `--dst-ip-col` o
  perfil): `shortcut.identifier` ya no las marca, y salen del hash de
  duplicados y conflictos, de modo que el mismo flujo visto desde otra IP u
  otra hora se cuenta como duplicado. Siguen siendo características para
  `shortcut.single_feature` y los checks de fuga. Las columnas solo detectadas
  por nombre se tratan como antes. El dataset de control, con los roles
  declarados, da verde.
- `labels.noise` no reporta por debajo del 0,1 % de filas (`noise_min_ratio`).

### Agregado

- `deploy/docker-compose.prod.yml`, `deploy/Caddyfile` y `docs/DESPLIEGUE.md`:
  la API detrás de Caddy con HTTPS, límite de cuerpo, cabeceras de seguridad,
  límites de memoria y sin puertos expuestos. Probado en local; nunca se corrió en
  un servidor.
- API: configuración centralizada y validada al arrancar (`vigia.api.config`),
  con las variables nuevas `VIGIA_MAX_QUEUED_JOBS`, `VIGIA_UPLOAD_TTL_MINUTES`,
  `VIGIA_REPORT_TTL_MINUTES`, `VIGIA_MAX_STORED_JOBS`, `VIGIA_STORAGE_QUOTA_MB`,
  `VIGIA_MAX_ROWS`, `VIGIA_MAX_EXPANDED_MB` y `VIGIA_ENV`.
- API: el panel se sirve con fallback de SPA (`/resultado/<id>` recargado
  devuelve el panel).
- `--time-format` en `vigia audit` y `vigia fix` (también `time_format` en
  `vigia.load`, en un perfil y en la petición de `/audits`), para columnas de
  tiempo con día y mes ambiguos.
- `vigia fix --profile`.
- `AuditContext.with_df(df)`: el mismo contexto sobre otro DataFrame.
- `VIGIA_DEBUG=1`: deja pasar el traceback original de un error inesperado.
- El perfil `ctu-13` declara `Sport` como puerto de origen, y `sport` se detecta
  como tal.
- El HTML y el panel muestran los checks que fallaron en una sección aparte.
- `dup.near` ya no se salta sobre 200.000 filas: revisa una muestra al azar y
  reporta una cota inferior.
- `labels.noise` declara cuánto pudo sobreestimar según la exactitud del modelo
  auxiliar (`sobreestimacion_maxima_observada`).
- Test de que el dataset de control da verde en CSV, Parquet, Zeek (TSV y JSON)
  y Suricata EVE.

- **Perfiles de los cuatro datasets restantes de R17** (`--profile`):
  `cse-cic-ids-2018`, `unsw-nb15`, `ugr-16` y `ctu-13`. Todos los valores
  salen de la documentación oficial de cada dataset; donde la fuente no los
  publica (IPs y ventanas de UNSW-NB15) el perfil no los inventa. Los de
  CSE-CIC-IDS2018 y CTU-13 se validaron contra los archivos reales.
- Perfil `unsw-nb15-raw` para los cuatro CSV crudos de UNSW-NB15, que se
  publican sin cabecera, y datos del GT oficial en `unsw-nb15` (atacantes,
  víctimas y jornadas de captura).
- Un perfil puede traer `label_groups` para agrupar una etiqueta con muchos
  subtipos por prefijo (la original queda en `__label_original`, que Vigía no
  cuenta como característica). `ctu-13` lo usa: 60 subtipos por escenario pasan
  a botnet, to_botnet, normal y background.
- `benchmarks/control_limpio.py`: dataset sintético sin defectos para medir falsos
  positivos, con un test de regresión. Con él se midió cuánto acierta
  `labels.noise` (ver `benchmarks/RESULTADOS.md`).
- Un perfil puede traer `csv_columns` para leer CSV **sin cabecera** (UGR'16).
- Vigía reconoce `.binetflow` y `.2format` (CTU-13) como CSV.
- Auditorías sobre datos reales de CSE-CIC-IDS2018 (10 archivos, 16,2 M de
  filas), UNSW-NB15 (archivos oficiales: training, testing y 4 crudos, 2,5 M de
  filas) y CTU-13 (13 escenarios, 20 M de flujos).
  Resultados y límites en `benchmarks/RESULTADOS.md`.

### Mejorado

- `dup.near` es 5 veces más rápido (`MinHash.bulk`, mismas firmas y mismo
  resultado): el testing-set de UNSW-NB15 pasó de 153 a 31 s.

### Corregido

- **Un fallo de entrenamiento en `labels.noise`, `poison.loss`, `drift.covariate` y
  `drift.concept` ya no figura como "no aplica"** con el texto de la excepción: va a
  `errors` (semáforo rojo, código 3) y, por la API, sin el mensaje. Los motivos de salto
  que salen por la API también se limpian de rutas e IPs.
- La CLI ya no imprime `sin hallazgos` en verde debajo de un semáforo rojo cuando solo
  hubo errores.
- **API: el límite de subida no cortaba nada.** El servidor recibía y escribía el
  cuerpo entero antes del `413`. Ahora un middleware rechaza por `Content-Length`
  y corta el stream sin él (chunked) al pasarse del límite.
- **API: subidas huérfanas y disco sin tope.** Las subidas que ningún trabajo
  usa se borran a los 30 minutos, hay una cuota de 2 GiB (`507`) y al arrancar se
  borran los directorios que dejó una ejecución anterior (salvo los de un proceso
  vivo).
- **API: validar una subida leía el archivo entero dentro del event loop.** Un
  Parquet de 114 KiB que descomprime a 50 M de filas agotaba la memoria y el
  servidor no contestaba. Ahora se mira el pie del Parquet y una muestra del CSV,
  en un hilo, con topes de filas y de memoria estimada.
- **API: rechazaba un CSV en Windows-1252** que la CLI sí lee (el día de ataques
  web de CIC-IDS2017).
- **Panel: "Ver el reporte HTML" daba 401 con clave configurada**; ahora se pide
  con la cabecera y se abre desde un Blob. El comando de "Corregir" usa un
  marcador `<archivo>` y las columnas de la auditoría, y las claves de React son
  únicas. Se quitó `VITE_API_KEY`, que dejaba la clave en el JavaScript servido.
- **API: recargar un enlace profundo del panel daba 404.**
- **API: el contador de peticiones crecía sin límite** y se evadía rotando
  `X-API-Key`.
- **API: el id del dataset llegaba sin validar a `glob`.** Un cliente podía
  auditar o borrar los datasets de otros (`*`, `?`, `[...]`) y alcanzar archivos
  fuera del directorio de subidas (`../x`). Hay que actualizar antes de exponer
  la API. La clave de API se compara en tiempo constante.
- **`leak.temporal` ya no da "sin hallazgo" con una fuga real.** Descartaba en
  silencio las filas cuyo tiempo no interpretaba, e interpretaba `07/08/2017`
  siempre como día/mes (un crítico falso del 100 % con fechas estadounidenses).
  Ahora se salta con el motivo (cuántos valores, o formato ambiguo). Si antes
  una auditoría tuya con fechas mezcladas daba verde, volvé a correrla.
  `temporal_split` usa el mismo parser y deja sin split las filas sin tiempo (las
  mandaba a prueba).
- **`vigia fix` y `vigia.benchmark.compare` usaban otra clave de deduplicación que `vigia audit`**
  cuando había columnas de rol declaradas: `drop_duplicates` no quitaba lo que
  `dup.exact` reportaba. `vigia fix --out` ya no puede pisar la entrada.
- **`shortcut.single_feature` ya no ignora las columnas continuas**: un umbral
  perfecto sobre una tasa o una duración no lo reportaba nadie.
- **`labels.noise` corre con una clase mayoritaria del 95 % o más** (no podía
  correr nunca, en la proporción habitual del tráfico real).
- `dup.near` ve el casi-duplicado de una fila repetida (agregar una copia exacta
  lo hacía desaparecer).
- `labels.conflict` no falla con filas sin etiqueta.
- `leak.session` exige las cinco columnas de la 5-tupla (corría con cuatro).
- `validity.constant` (y `drop_constant`, y `--streaming`) ignoran los nulos.
- `shortcut.identifier` ya no marca "ruido", "guide" ni `flow_idle_time`; antes
  `drop_identifiers` las borraba.
- `--streaming` detecta la etiqueta y el split por nombre, quita los espacios de
  los nombres (`--label-col Label` sobre `" Label"` fallaba) y lista
  `dup.cross_split` como saltado cuando no corre.
- `run_audit` y `run_streaming_audit` registran la versión real, no `0.1.0`.
- `release.yml` corre los tests antes de publicar, verifica que el tag coincida
  con la versión y fija las actions por SHA. El sdist ya no arrastra
  `web/node_modules` (pesaba 28,6 MB en una copia con el panel instalado).
- Documentación: README, PLAN, CHECKS, DERIVA, USO y ARQUITECTURA dejan de
  afirmar lo que no era cierto (requisitos P0 completos, `xxhash`, el límite de
  subida que "corta", el volumen que "no crece"). La cifra de 2.867 infinitos de
  CIC-IDS2017 queda marcada como pendiente de re-medir.
- El lector de Suricata dejaba la columna `event_type` al filtrar por un tipo, y
  `validity.constant` la reportaba como defecto en cualquier EVE de flujos.

- `labels.noise` lanzaba un pool de procesos de cleanlab que, en Windows,
  relanzaba en cadena el script que usaba Vigía como librería sin la guarda
  `if __name__ == "__main__"`. Ahora usa un solo proceso.
- El hallazgo de `labels.noise` aclara que el estimado incluye el solapamiento
  natural entre clases (con clases muy solapadas marcó 6 a 8 % sin ruido real).
- **Lectura de CSV: decimales tardíos se convertían en nulos sin avisar.** El
  tipo de cada columna se infería con las primeras 10.000 filas; si una columna
  parecía entera y luego traía decimales, `ignore_errors=True` los volvía nulos
  y `validity.nan_inf` los reportaba como datos corruptos (en CSE-CIC-IDS2018:
  55.796 valores falsos en un archivo y 7,37 millones en otro). Ahora las
  columnas enteras se leen como `Float64` y vuelven a entero si todos sus
  valores lo son. En CIC-IDS2017 hubo 9 nulos falsos (en el archivo de
  infiltración del jueves) y alcanzaron para mover las cifras A y B de
  `benchmarks/cic_antes_despues.py`; ver "Por qué cambiaron A y B" en
  `benchmarks/RESULTADOS.md`. (Esta entrada decía que en CIC-IDS2017 no había
  ningún nulo falso y que los benchmarks publicados no cambiaban.)
- `--streaming` ignoraba `--profile`: no aplicaba la columna de etiqueta ni los
  nombres de un CSV sin cabecera, y no mostraba los errores conocidos.
- `validity.impossible` fallaba con `OverflowError` en columnas enteras chicas
  (`Int8`/`Int16`) cuyo nombre contiene "port", dejando el check sin correr.
- La API ya no expone la ruta interna del servidor en los resultados: el
  campo `dataset.path` devuelve `dataset:<id>`.
- El directorio temporal de subidas se borra al salir el proceso.

### Límites conocidos

Declarados en [`docs/PLAN.md`](docs/PLAN.md) y medidos en
[`benchmarks/RESULTADOS.md`](benchmarks/RESULTADOS.md): UGR'16 no se audita con
archivos oficiales (el sitio oficial dio 403 y ninguna otra fuente trae flujos);
CSE-CIC-IDS2018 no trae IPs ni split en su versión procesada y su `Timestamp`
no tiene AM/PM; `dup.near` y `labels.noise` trabajan con muestras en datasets
grandes; `labels.noise` no separa el ruido del solapamiento de clases.

Además: `drift.concept` está calibrado con datos sintéticos y todavía no se
midió sobre tráfico real; y la API no aísla a los
clientes que comparten la clave ni tiene tope de tiempo por trabajo (ver
[`docs/DESPLIEGUE.md`](docs/DESPLIEGUE.md)).

## [0.2.0] - 2026-09-29

### Agregado

- El paquete se publica en PyPI como `vigia-nids` (el nombre `vigia` estaba
  tomado); el comando y el paquete importable siguen siendo `vigia`.
- **Perfiles de datasets conocidos** (`vigia.profiles`, requisito R17):
  `--profile cic-ids-2017` en `vigia audit` (y `vigia.load(profile=...)` en el
  SDK) fija los roles de columna y expone IPs atacantes, ventanas de ataque y
  errores conocidos documentados por el CIC, sin que un `--label-col` u otro
  flag explícito pierda prioridad sobre el perfil.
- **`dup.near`** (requisito R2, casi-duplicados): MinHash LSH (extra opcional
  `ml`, agrega `datasketch`) para encontrar filas casi idénticas que
  `dup.exact` no detecta por no ser copias byte a byte. Umbral configurable
  con `near_duplicate_threshold`.
- **API REST** (`vigia.api`, extra opcional `api`): FastAPI con endpoints para
  subir datasets, lanzar auditorías, envenenamiento y deriva de forma
  asíncrona (cola en proceso con `asyncio`, sin Celery ni Redis), consultar
  estado y descargar el reporte HTML. Autenticación por `X-API-Key`, límite de
  subida y de peticiones por minuto configurables por variable de entorno, y
  borrado automático del dataset subido al terminar el trabajo.
- Comando `vigia serve` para levantar la API con uvicorn.
- **Panel web** (`web/`, React + Vite + TypeScript): subir un dataset, ver el
  resultado (semáforo, hallazgos, checks no ejecutados), correcciones
  sugeridas y comparación de deriva con PSI por columna. El semáforo gris
  tiene la misma jerarquía visual que el rojo: nunca se confunde "no se pudo
  revisar todo" con "está limpio". `docker compose up` sirve la API y el
  panel juntos en un solo puerto.

## [0.1.0] - 2026-09-22

Primera versión funcional. Los tres módulos implementados y validados contra
datos reales.

### Agregado

- **Módulo 1 — Auditor** (`vigia audit`): 15 checks que cubren los diez
  requisitos P0 (duplicados, validez, fugas entre entrenamiento y prueba,
  ruido de etiqueta), validados contra CIC-IDS2017 y contra Engelen et al.
- **Módulo 2 — Envenenamiento** (`vigia poison`): 4 detectores, medidos sobre
  tráfico real con ataques inyectados.
- **Módulo 3 — Deriva** (`vigia drift`): 4 checks, medidos sobre los cinco
  días de CIC-IDS2017.
- 8 correcciones automáticas, con cuarentena de las filas afectadas.
- Lectores de CSV, Parquet, Zeek, Suricata EVE y PCAP (R13 y R14).
- CLI con 7 comandos y códigos de salida 0/1/2 para integrarse en CI.
- Reporte HTML y JSON, con semáforo rojo/amarillo/verde/gris.
- 188 tests, `ruff` y `mypy` limpios.
- Documentación: arquitectura, checks, uso, deriva y envenenamiento en
  [`docs/`](docs/).

[1.0.3]: https://github.com/Joshua203-byte/vigia-nids/releases/tag/v1.0.3
[1.0.2]: https://pypi.org/project/vigia-nids/1.0.2/
[1.0.1]: https://pypi.org/project/vigia-nids/1.0.1/
[1.0.0]: https://pypi.org/project/vigia-nids/1.0.0/
[0.2.0]: https://pypi.org/project/vigia-nids/0.2.0/
[0.1.0]: https://pypi.org/project/vigia-nids/0.1.0/
