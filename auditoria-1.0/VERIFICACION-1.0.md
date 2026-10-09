# Verificación de la remediación de Vigía 1.0

Revisión del 06/10/2026 sobre `despliegue-1.0` (`efc13aa`, 56 commits sobre `main` `35da75a`).

> El historial de commits de este proyecto no se publica: este repositorio parte de
> un solo commit. Los hashes que se citan en este archivo son del historial
> original y no se pueden consultar aquí; los tests de cada corrección sí están
> en `vigia/tests/`.

> **Límite de esta revisión, dicho antes que nada.** El plan pide un revisor que no
> haya participado. Quien hizo esta verificación es la misma sesión de Claude que
> escribió la segunda tanda de correcciones (y, antes de que el contexto se resumiera,
> la primera). No es independiente. Lo compenso corriendo cosas que el autor no había
> corrido (otro sistema operativo, un entorno limpio, el CI remoto, datos nuevos,
> sockets crudos), pero conviene que alguien que no haya visto el código lea los
> hallazgos `VER-01` a `VER-04` y los reproduzca.
>
> Cambio de contexto respecto del plan: `despliegue-1.0` **ya se empujó** a `origin`
> (a pedido de Joshua) y el CI remoto corrió. Lo uso como evidencia.

---

## 1. Veredicto

| Pregunta | Respuesta | Lo que bloquea |
|---|---|---|
| ¿Se pueden mergear las dos ramas en `main`? | **Todavía no.** Técnicamente se mergean sin conflictos (`git merge-tree` limpio; `main` no se movió) y las dos puntas pasan sus suites, pero el CI de la rama está **rojo en todas las celdas** | VER-02 (un test frágil, arreglo de minutos) |
| ¿Se puede taggear la v1.0.0? | **No.** | VER-01 (`pip install vigia-nids` en un entorno limpio deja la CLI sin arrancar), VER-02 (CI rojo), VER-03 y VER-04 (`drift.concept`, el check nuevo, da falsos positivos críticos y altos en casos corrientes) |
| ¿Se puede desplegar? | **Sí, desde el punto de vista del código, para pocos clientes de confianza**, una vez que el CI esté verde. La imagen y el compose de producción funcionan; no los afecta VER-01 (la imagen trae `click` por `uvicorn`) | Lo que falta no es código: dominio, servidor, publicar la imagen. Ver el punto 6 para lo que conviene antes de abrirlo a más clientes |

**Qué sí está bien.** De las 33 correcciones verificadas, 30 hacen lo que dicen y el
test falla en el código anterior. Las que no son completas son tres
(`SCI-03`, `SEC-06`, `CI-01/CI-02` en lo que cubren), todas con hallazgo propio abajo.

---

## 2. Tabla de verificación

"Falla antes" = el test nuevo falla (o ni siquiera importa) con el commit padre,
corrido en un `git worktree` con los archivos de test del commit encima. Los tests
que **pasan** antes, y por qué eso es razonable, están marcados.

### Sección 8 (primera tanda, `auditoria-1.0`)

| ID | ¿El test falla antes? | ¿Completa? | Veredicto | Nota |
|---|---|---|---|---|
| SEC-01 | Sí (3 de 3) | Sí | OK | `dataset_id` y `reference_id` pasan por `OpaqueId`; `job_id` por `Path(pattern)`; `storage._candidates` revalida y resuelve dentro del directorio. No encontré un camino a `storage` sin validar (rutas, jobs, llamadas internas) |
| SEC-11 | n/a (sin test; es de tiempo) | Sí | OK | `hmac.compare_digest` sobre bytes |
| COR-01 | Sí (3 de 3 y `--profile`) | Sí | OK | |
| SCI-01 / SCI-02 | Sí (4 de 4; `time_format` 3 de 3) | Sí | OK | Medí ISO, ISO con `T`/`Z`, `datetime` nativo, epoch en s, ms y float, `mm/dd/aaaa` y `dd/mm/aaaa` con días > 12: ninguno da "ambiguo" ni se salta. Solo se salta lo realmente ambiguo |
| SCI-09 | Sí (2 de 2) | Sí | OK | |
| SCI-04 | Sí (2 de 2) | Parcial, declarado | OK | `compare()` no garantiza las mismas filas de test: `drop_duplicates` las cambia a propósito y lo avisa (`test_changed`). `test_changed` solo compara el **conteo** de filas de prueba: un cambio de filas con igual conteo no se avisaría (raro; Baja) |
| SCI-03 | Sí (el módulo nuevo ni importaba) | **No** | **Incompleto** | Mide la relación con la etiqueta, pero con falsos positivos: VER-03 y VER-04 |
| SCI-05 | Sí (1 de 1; el control de ruido ya pasaba, como corresponde) | Sí | OK | Ruido continuo independiente de la etiqueta: **0 falsos positivos en 80 corridas** (n de 60 a 20.000; 2 y 5 clases; desbalanceo 95/5; 40 columnas). Sin regresión de tiempo (ver el punto 4) |
| COR-03, SCI-06, SCI-08, COR-12 | Sí | Sí | OK | |
| COR-04 | Sí (3 de 3) | Sí | OK | Cambio de comportamiento esperado: con 4 de 5 columnas de la 5-tupla `leak.session` se salta (en el dataset demo ya no sale su crítico) |
| COR-13 | Sí (el de "palabras" falla; el de "identificadores reales" ya pasaba: es el control) | Sí | OK | |
| COR-15, COR-16 | Sí | Sí | OK | |
| SCI-07 | Sí (5 de 5) | Sí | OK | Una columna de texto cuyos únicos valores son `NaN`/`Infinity` pasa a `Float64`: es consecuencia directa de la regla elegida. Una de texto mezclado queda como texto |
| COR-02 | Sí (4 de 4) | Sí | OK | |
| COR-05 | Sí | Sí | OK | Hay un único `traffic_light()` y todos los caminos (CLI, HTML, API, panel) lo usan: rojo con errores. Un detalle cosmético: VER-06 |
| COR-08, DIS-02 | Sí (4 de 5; el que ya pasaba es el control del `--fail-on`) | Sí | OK, con VER-01 | El `import click` que trajo este commit es VER-01 |
| CI-01 | Sí / n/a | Parcial | **Incompleto** | `release.yml`: los 5 SHA existen (`gh api`), `actionlint` limpio, permisos mínimos. Pero el job `test` instala `[dev,ml,parquet,api]` y por eso no ve VER-01: publicaría una rueda cuya CLI no arranca |
| CI-04 | — | — | No re-verificado | No reconstruí el sdist |
| CI-05 | n/a | Sí | OK | |

### Sección 9 (segunda tanda, `despliegue-1.0`)

| ID | ¿El test falla antes? | ¿Completa? | Veredicto | Nota |
|---|---|---|---|---|
| Configuración | Sí (módulo nuevo) | Sí | OK | |
| SEC-05 | Sí | Sí | OK | Probado además con **sockets crudos** contra la API en el contenedor: `Content-Length` negativo, repetido o no numérico → 400; 10 GB declarados sin enviar → 413 sin leer; `Content-Length` mayor que el cuerpo real con cierre a la mitad → conexión cerrada, sin archivos a medias; chunked cortado → 400; `/health` sigue. Ninguno dejó archivos en `/data/uploads` |
| SEC-02 | Sí | Sí | OK | La rama `fcntl.flock` **sí** funciona en Linux: tras `docker kill` y arranque, el directorio de la ejecución anterior se borró y se creó uno nuevo. Los tests de la rama de Linux los corrí en un contenedor `python:3.12-slim`: 91 de 92 pasan; el que falla es VER-02 |
| Tope de trabajos y caducidad | Sí | Sí | OK | La lista de ids caducados está acotada (1.000). No hay fuga de memoria. Un `SystemExit` dentro de un trabajo no deja la cola atascada: tumba el event loop (el proceso), lo cual no es un riesgo realista |
| SEC-04, PERF-02 | Sí (el Parquet normal ya pasaba: control) | Sí | OK | Un Parquet de 34 MB con 4 M × 80 se acepta en segundos por metadatos |
| COR-06 | Sí | Sí | OK | |
| SEC-03 | Sí | Sí | OK | Con Caddy delante, `X-Forwarded-For: 9.9.9.9` mandado por el cliente **no** llega a la API (el log muestra `172.28.0.1`). La API no publica puertos; `FORWARDED_ALLOW_IPS` es `172.28.0.0/24`, no `*` |
| SEC-06 | Sí (3 de 3) | **No** | **Incompleto** | VER-05: cinco `CheckSkipped(f"...{exc}")` llevan el texto de la excepción a `skipped`, que sale por la API sin sanear |
| COR-09 | Sí | Sí | OK | Probé 5 variantes de traversal (`..%2f`, `%2e%2e`, `%5c`, doble codificación, bajo `/assets`): todas devuelven el `index.html` del fallback, ninguna un archivo del servidor |
| SEC-12 | Sí | Sí | OK | |
| SEC-09 | Sí / manual | Sí | OK | Los 3 digests existen (la imagen se construyó y Caddy arrancó con ellos); `/app/web/dist` y `/app/src` de solo lectura; el contenedor corre con el sistema de archivos de solo lectura. Ver VER-09 por el margen de memoria |
| COR-07, COR-10, COR-11, SEC-08 | n/a (sin tests de front) | Sí | OK | Recorrí el panel en Chrome real contra el compose de producción. Con la CSP de Caddy **no hubo ninguna violación de CSP** en el panel ni en la pantalla de deriva con gráficos |
| Problema nuevo 1 | Sí | Sí | OK | |
| CI-02 (parcial) | n/a | Parcial | Incompleto | SHAs verificados, `actionlint` limpio; pero el CI quedó rojo (VER-02) y falta un job que instale la rueda sin extras (VER-01) |

---

## 3. Hallazgos nuevos

### VER-01 — La CLI no arranca con una instalación limpia
- **Severidad:** Alta · **Estado:** CONFIRMADO
- **Ubicación:** `vigia/src/vigia/cli.py:11` (`import click`) y `:135`; introducido en `4be02a2`
- **Escenario:** `typer` 0.27.2 ya no depende de `click` (trae el suyo en `typer._click`).
  El `pyproject.toml` solo declara `typer>=0.12`, así que `pip install vigia-nids` en un
  entorno nuevo no instala `click` y **todo comando de `vigia` falla** con
  `ModuleNotFoundError: No module named 'click'`. En el venv del proyecto y en el CI
  `click` llega por `uvicorn` (extra `api`), por eso nada lo vio.
  Segundo efecto: con ambos instalados, `click.ClickException` y la de Typer son clases
  distintas (`issubclass(typer.BadParameter, click.ClickException)` da `False`), así que
  la guarda `_guarded` no reconoce los errores de uso de Typer.
- **Reproducción:** `python -m venv v && v/Scripts/pip install vigia_nids-1.0.0-py3-none-any.whl && v/Scripts/vigia version`
  (la rueda se construyó con `pip wheel . --no-deps`). Con `click` instalado a mano, el
  resto anda: `audit`, `fix` y `drift` sin `[ml]` corren y los checks que necesitan
  scikit-learn se saltan diciéndolo.
- **Corrección sugerida:** sacar `import click`; en `_guarded`, dejar pasar
  `typer.Exit`, `typer.Abort` y toda excepción con `format_message` (los errores de uso de
  cualquiera de las dos clases), sin importar `click`.
- **Test que habría que agregar:** un job de CI que instale **solo la rueda** en un venv
  limpio y corra `vigia version` y `vigia checks`; y en `release.yml`, el mismo paso
  sobre la rueda construida, antes de publicar.

### VER-02 — El CI de la rama está rojo en todas las celdas
- **Severidad:** Alta (bloquea el merge) · **Estado:** CONFIRMADO
- **Ubicación:** `vigia/tests/unit/test_api_trabajos.py::test_un_dataset_en_la_cola_no_caduca_por_ttl_de_subida`
- **Escenario:** el test avanza un reloj falso a `1000 + 3600` y exige
  `purge_expired_uploads() == []`. Pero otras subidas sin trabajo de tests anteriores
  (`test_api_limites.py`) siguen registradas con la hora **real** de `time.monotonic()`.
  En Windows, con la máquina encendida hace días, esa hora es mayor que la del reloj
  falso y no vencen; en Linux, donde `monotonic` es el tiempo desde el arranque (un
  runner de CI: minutos), sí vencen y aparecen en la lista. Falla igual en Docker.
  Es un defecto del test, no del producto.
- **Reproducción:** `gh run view 37394171824 --log-failed` (1 failed, 410 passed) o los
  tests de `tests/unit/test_api*.py` dentro de `python:3.12-slim`.
- **Corrección sugerida:** que el test compare solo su propio id
  (`assert dataset_b not in purged`) y que una fixture `autouse` vacíe el registro de
  subidas entre tests.
- **Test que habría que agregar:** el mismo, corrido sobre un reloj falso que parta de
  un valor chico.

### VER-03 — `drift.concept` da crítico con un lote de una sola clase
- **Severidad:** Media · **Estado:** CONFIRMADO
- **Ubicación:** `vigia/src/vigia/drift/checks.py`, `ConceptDriftCheck.run` (el cálculo de `en_lote` y `caida`)
- **Escenario:** la exactitud balanceada de un lote que tiene una sola clase es la
  *recall* de esa clase; la de la referencia es el promedio de todas. Si el modelo
  reconoce peor la clase rara (o la que el lote trae), la "caída" sale de comparar
  cosas distintas. Un lote de solo ataques de la **misma** distribución que la
  referencia dio **crítico en 5 de 6 semillas** (caída 0,30 a 0,33) y alto en la otra.
  Un lote de pura clase mayoritaria o el lote completo no dan nada.
- **Reproducción:** `vigia/` + script `v03_concept2.py` (anexo): referencia y lote de 6.000
  filas de la misma generadora, ataque raro (4 %), se filtra el lote a `attack`.
- **Corrección sugerida:** comparar contra la referencia las mismas clases que tiene el
  lote (o el *recall* por clase, que el hallazgo ya calcula), y saltarse con motivo si el
  lote trae menos de 2 clases.
- **Test:** referencia y lote de la misma distribución, lote filtrado a una clase:
  `drift.concept` no puede reportar.

### VER-04 — `drift.concept` da alto con duplicados exactos en la referencia
- **Severidad:** Media · **Estado:** CONFIRMADO
- **Ubicación:** misma, la validación cruzada de la referencia (`cross_val_predict`)
- **Escenario:** si la referencia trae filas repetidas (cosa habitual en datasets de
  flujos, y que el propio auditor reporta como `dup.exact`), la validación cruzada
  "ve" la fila en el entrenamiento y en el pliegue de prueba y sobreestima
  `exactitud_balanceada_referencia`; el lote, que no las tiene, rinde menos y la
  diferencia parece deriva. Referencia con cada fila ×4 y lote nuevo de la misma
  distribución: **alto en 6 de 6 semillas** (caída de 0,13 a 0,20).
- **Reproducción:** `v03_concept2.py`, bloque B.
- **Corrección sugerida:** deduplicar la referencia (o agrupar la validación cruzada por
  el hash de fila) antes de calcular `en_ref`.
- **Test:** referencia con duplicados, misma distribución, sin hallazgo. Los umbrales de
  0,10 y 0,25 resistieron 180 corridas **sin** duplicados ni lote de una clase
  (0 falsos positivos con n de 200 a 5.000 y ruido de 0,1 a 3; con ruido alto el check se
  salta, que es lo correcto).

### VER-05 — El texto de excepciones sigue saliendo por la API en los motivos de salto
- **Severidad:** Baja · **Estado:** CONFIRMADO
- **Ubicación:** `label_noise.py:168,197`, `drift/checks.py:355,501`, `poison/detectors.py:177`
- **Escenario:** `CheckSkipped(f"no se pudo ...: {exc}")` mete el mensaje de scikit-learn,
  cleanlab o LightGBM en `report.skipped`, y `_anonymize` solo sanea `errors`. Con un
  `RandomForestClassifier.fit` que lanza `ValueError("C:/srv/.../secreto.csv fila: 10.0.0.5,...")`
  el texto sale tal cual en `result.skipped` de `/drift`.
- **Reproducción:** `v10_skip_leak.py` (anexo).
- **Corrección sugerida:** en `_anonymize`, aplicar el mismo tratamiento a los motivos de
  salto que contienen `{exc}`, o dejar el detalle en el log y que el `CheckSkipped` diga
  solo el tipo. De paso: un fallo de entrenamiento es un defecto, no "no aplicaba" (hoy da
  gris, no rojo).
- **Test:** el de `test_api_errores.py` pero con un check que se salta con `{exc}`.

### VER-06 — La CLI dice `sin hallazgos` en verde debajo de un semáforo ROJO
- **Severidad:** Baja · **Estado:** PROBABLE (leído en el código, no ejecutado)
- **Ubicación:** `vigia/src/vigia/cli.py:56-59` (`_print_summary`)
- **Escenario:** con errores y ningún hallazgo, imprime `Semáforo: ROJO` y, en la línea
  siguiente, `sin hallazgos` en verde. El código de salida y el aviso posterior son
  correctos; es la línea de conteo la que contradice al semáforo.
- **Corrección sugerida:** cuando hay `errors`, no pintar "sin hallazgos" en verde.
- **Test:** salida de `_print_summary` con un reporte de solo errores.

### VER-07 — El conteo de checks de la documentación está desfasado en uno
- **Severidad:** Baja · **Estado:** CONFIRMADO
- **Ubicación:** `README.md:36`, `docs/PLAN.md:20`, `CHANGELOG.md` ("26 en total")
- **Escenario:** el registro tiene **25** checks (16 del auditor, 4 de envenenamiento, 5 de
  deriva) y las clases con `id = ` suman 25. Los documentos dicen 26 (17 + 4 + 5). El 17
  ya estaba mal en `main` (decía 25 con 24 reales); la primera tanda le sumó el de deriva
  sobre esa base.
- **Reproducción:** `python -c "from vigia.core.registry import all_checks; print(len(all_checks(None)))"`.
- **Corrección sugerida:** 25 (16 + 4 + 5) en los tres lugares.

### VER-08 — El valor por defecto de la cuota difiere entre el código y `DESPLIEGUE.md`
- **Severidad:** Baja · **Estado:** CONFIRMADO
- **Ubicación:** `docs/DESPLIEGUE.md` (tabla de variables) contra `api/config.py` y `USO.md`
- **Escenario:** `VIGIA_STORAGE_QUOTA_MB` es 2048 en el código y en `USO.md`, y 4096 en el
  compose de producción y en la tabla de `DESPLIEGUE.md`, bajo la columna "Por defecto".
  Es una decisión legítima (el compose la sube) pero la tabla no lo dice.
- **Corrección sugerida:** rotular la columna "En el compose" o aclararlo.

### VER-09 — Los topes de filas y de memoria no están atados al pico medido
- **Severidad:** Baja (hoy) · **Estado:** PROBABLE
- **Ubicación:** `api/config.py` (`VIGIA_MAX_ROWS`, `VIGIA_MAX_EXPANDED_MB`) y `deploy/docker-compose.prod.yml` (`mem_limit: 6g`)
- **Escenario:** el pico medido fue 5,4 GiB para 1 M × 80 (≈ 640 MB crudos, un factor de
  ~8,4). La API acepta hasta 4 GiB estimados (filas × columnas × 8) y 5 M de filas, o sea
  un pico potencial muy por encima de los 6 GiB del contenedor, que lo mata y lo reinicia
  (con lo que se pierde toda la cola). Con 1 M × 80 el margen es de ~0,6 GiB.
  **No pude reproducir un OOM** con datos sintéticos: 3 M × 80 de enteros y 4 M × 80 de
  flotantes (esquema comprimible) llegaron a 2,1 y 2,7 GiB y terminaron en 24 y 30 s sin
  que Docker matara nada. El riesgo depende de datos reales con cadenas y columnas de alta
  cardinalidad.
- **Corrección sugerida:** derivar el tope de `VIGIA_MAX_EXPANDED_MB` de `mem_limit` con el
  factor medido (≈ 8×), o bajarlo a unos 700 MB.

---

## 4. Regresiones y diferencias entre `main` y `despliegue-1.0`

**Benchmarks sintéticos** (mismos archivos, mismo comando, una y otra rama):

| Dataset | `main` | `despliegue-1.0` | Explicación |
|---|---|---|---|
| `control_limpio` (sin declarar roles) | rojo, `shortcut.identifier` alto | igual | Misma salida: no es una regresión (el control da rojo sin declarar roles en las dos ramas) |
| `make_demo_dataset` | 12 hallazgos, `leak.session` crítico | 13 hallazgos; `leak.session` saltado; 4 `shortcut.single_feature` en vez de 2 | `leak.session` ya no corre con 4 de 5 columnas (COR-04); más columnas continuas detectadas (SCI-05) |

**Rendimiento** (1 M de filas × 46 columnas sintéticas, todos los checks, con otras
cargas en la máquina): `main` 187 s, pico 2,85 GiB; `despliegue-1.0` 185 s, pico 2,49 GiB.
**Sin regresión.** La discretización de SCI-05 no se nota en este dataset.

**Contrato.** Cambios visibles que están en el CHANGELOG: `drift.concept` pasa a
`drift.covariate`, `schema_version`/`errors`/`n_errors`, código de salida 3, `fix` con 2,
`--time-format`, `fix --profile`, 200 MB, un trabajo a la vez, `VIGIA_ENV`, errores con id,
limitador por IP, y los códigos `410`, `503`, `507`. No encontré un cambio de contrato que
falte en el CHANGELOG. Lo único que el usuario nota y que ninguna nota advierte: con
`typer` 0.27 la rueda no arranca sin `click` (VER-01).

**Rueda en un entorno limpio, sin `[ml]`:** ver VER-01. Con `click` instalado a mano,
`vigia version`, `checks`, `audit`, `fix` y `drift` funcionan; `drift` marca gris y dice
que `drift.concept` y `drift.covariate` necesitan scikit-learn.

**Integridad de las ramas.** Suite completa en 10 commits: `be60f8a` (352), `8fa78ae` (293),
`9833c45` (309), `f5b3540` (344), `58a9333` (342), `664597a` (374), `118a81f` (385),
`dc467ac` (399), `1766750` (410) y `efc13aa` (411): todos verdes. Cuatro de las primeras
corridas fallaron por **correr varias suites en paralelo con el mismo `TMPDIR`**: los
commits anteriores a SEC-02 se borraban unos a otros los directorios de subida. Con un
`TMPDIR` por corrida pasan. Es un efecto de mi método, pero confirma el hallazgo que
SEC-02 corrige. Los commits no mezclan cambios sin relación, salvo dos que agrupan
hallazgos del mismo archivo (`b0c16c2` con cuatro del panel, `d0e0567` con SEC-04, PERF-02
y COR-06). No hay secretos ni binarios versionados (`deploy/` solo trae el ejemplo de
`.env`).

---

## 5. Hipótesis descartadas y áreas sin hallazgos

- **Un trabajo con `BaseException` deja la cola atascada.** No: un `SystemExit` sube hasta
  el event loop y tumba el proceso; un `CancelledError` sí libera su lugar. No hay una
  fuente realista de `BaseException` en los checks.
- **Archivos de spool de Starlette que quedan en el volumen tras un `kill`.** No: en Linux
  son archivos sin nombre y desaparecen con el proceso (probado con un `docker kill`
  en plena subida). Sí consumen disco fuera de la cuota mientras dura la subida.
- **`X-Forwarded-For` falsificable.** No a través de Caddy (lo reemplaza) ni llegando a la
  API (no publica puertos, y uvicorn solo confía en la red del proxy).
- **Path traversal en el fallback de SPA.** No (5 variantes, incluido `%5c`).
- **CSP del `Caddyfile` rota el panel.** No: sin violaciones, también en Deriva con gráficos.
- **La CSP no se aplica al reporte abierto como `blob:`.** Se aplica: el documento hereda
  la política de quien lo creó. Un `<script>` inline agregado al reporte quedó bloqueado
  (`script-src 'self'`) y los estilos del reporte se aplican. Pero el `blob:` comparte
  **origen** con el panel (puede leer su `sessionStorage`, donde hoy solo están las columnas
  de la auditoría, no la clave). **Sin Caddy no hay CSP**, y ahí un script en el reporte sí
  correría; hoy la plantilla no tiene ninguno.
- **Falsos "ambiguo" en `leak.temporal` con ISO, epoch o `datetime`.** No.
- **Falsos positivos de SCI-05.** No (0 en 80 corridas).
- **Límite de subida eludible con `Content-Length` falso, repetido, negativo o chunked.** No.
- **Un directorio de otro proceso vivo borrado al arrancar.** No (candado probado en
  Windows con tests y en Linux con un reinicio real).
- **Caducidad que deja crecer la lista de ids caducados.** No (tope de 1.000).

---

## 6. Lo que queda abierto: clasificación y pasos

| Problema | ¿Bloquea? | Por qué |
|---|---|---|
| VER-01 (CLI sin `click`) | **Tag** | Una instalación limpia no arranca |
| VER-02 (CI rojo) | **Merge y tag** | Un test frágil; arreglo corto |
| VER-03, VER-04 (`drift.concept`) | **Tag** | Es el check que da nombre a la corrección más grande de la primera tanda y avisa "crítico" en casos corrientes. Una misma causa (la métrica compara cosas distintas): se arreglan juntos |
| VER-05 (motivos de salto con texto de excepción) | Puede esperar, antes de abrir la API a clientes que no sean de confianza | Fuga acotada a mensajes de scikit-learn y cleanlab |
| VER-06, VER-07, VER-08 | Puede esperar | Cosmético y documentación |
| VER-09 (topes frente al pico de memoria) | Puede esperar | `mem_limit` protege al servidor; el costo es un reinicio |
| **Problema 5** (sin tope de tiempo por trabajo) | **No bloquea el tag. Puede esperar** si los clientes son los pocos de confianza del escenario | Mi posición: no encontré un bucle infinito, pero un trabajo dura en proporción a las filas (≈ 3 min por millón; hasta 5 M de filas por trabajo) y con 1 corriendo y 4 en cola, un cliente con la clave puede mantener el servicio ocupado horas. Conviene un tope antes de dar la clave a alguien que no sea de confianza. Matar un hilo no se puede: el tope real exigiría correr el trabajo en un proceso aparte |
| **Problema 1** (recargar pierde la clave) | **Puede esperar** | Mi posición: `sessionStorage` sería un riesgo **aceptable aquí**: es por pestaña, se borra al cerrarla, y bajo la CSP de Caddy (`script-src 'self'`, sin scripts de terceros) un XSS tendría que originarse en el propio panel. No lo haría en una instalación **sin** Caddy. Confirmé además que el enlace profundo recargado hoy da 401 sin reintento |
| **SEC-07** (filas e IPs reales en los reportes, una clave compartida) | **Puede esperar**, pero hay que decirlo | Es una limitación del modelo (sin cuentas): no se arregla con código chico. Para pocos clientes de confianza es aceptable. Lo que sí hace falta es que `DESPLIEGUE.md` lo diga sin rodeos ("no hay aislamiento entre clientes: quien tenga la clave puede leer los reportes de otro si conoce el id") |
| Problema 6 (limitador después de leer el cuerpo) | Puede esperar | Acotado por el límite de subida |
| Problema 7 (Caddy rechaza un archivo de exactamente el límite) | Puede esperar | Lo razoné, no lo reproduje; es un margen de cientos de bytes |
| Problema 8 (la rama de Linux no se había probado) | **Cerrado**: la probé | El único test que falla en Linux es VER-02 |
| Problema 9 (los workflows no se pueden ejecutar) | Parcialmente cerrado | `ci.yml` corrió: ver VER-02. `release.yml` solo corre con un tag |
| Problemas 2, 4, 5, 6, 7, 9 de la sección 8 | Pueden esperar | Sin cambios |

**Pasos hasta el tag y el despliegue, en orden**

1. Arreglar VER-02 (test) y empujar: el CI tiene que quedar verde en las 7 celdas
   (Windows y Linux, 3.11 a 3.13).
2. Arreglar VER-01 (sin `import click`) y agregar al CI y a `release.yml` la instalación de
   la rueda sin extras con `vigia version` y `vigia checks`.
3. Arreglar VER-03 y VER-04 (una sola causa) con sus tests; volver a medir con varias
   semillas.
4. Arreglar VER-07 (25 checks) y VER-08.
5. Mergear `auditoria-1.0` y `despliegue-1.0` en `main` (se hacen sin conflictos).
6. Decidir cómo numerar lo que está bajo `[Unreleased]` y recién ahí taggear.
7. Para desplegar: dominio, servidor, imagen en GHCR, `deploy/.env`, y la primera
   corrida real de Caddy. Antes de dar la clave a alguien que no sea de confianza:
   VER-05, un tope de tiempo por trabajo y la aclaración de SEC-07 en `DESPLIEGUE.md`.

---

## 7. Anexo

Todo se corrió con el venv del proyecto (`vigia/.venv`) y se escribió fuera del repo, en
el directorio temporal de la sesión (`%TEMP%\ver\`). Nada de lo versionado se tocó; los
`git worktree` usados se eliminaron al terminar.

**Suite por commit.** `git worktree add --detach <dir> <hash>` y
`PYTHONPATH=<dir>/vigia/src python -m pytest -q` desde `<dir>/vigia`, con
`TMP`/`TEMP`/`TMPDIR` propios. Resultado: los 10 commits del punto 4 en verde.

**El test falla antes del arreglo.** `parent_check.py`: por cada commit, un worktree del
padre, se copian encima los archivos de test del commit y se corren. Resumen: todos los
tests nuevos fallan o no importan, salvo los controles negativos
(`test_ruido_continuo_puro_no_se_reporta`, `test_los_identificadores_reales_se_siguen_reconociendo`,
`test_cli_con_hallazgos_que_alcanzan_fail_on_gana_el_1`,
`test_la_version_sale_de_los_metadatos_y_coincide_con_pyproject`,
`test_un_parquet_normal_sigue_subiendo_con_sus_filas_y_columnas`), que pasan antes por
diseño.

**CI remoto.** `gh run view 37394171824 --log-failed`: `1 failed, 410 passed`; falla
`test_api_trabajos.py::test_un_dataset_en_la_cola_no_caduca_por_ttl_de_subida` en las
celdas de Linux (las de Windows se cancelaron por el `fail-fast`). Los jobs `web` y `docker` pasaron.

**Linux.** `docker run --user root -v tests:/t:ro --entrypoint sh <imagen> -c "pip install pytest httpx; pytest /t/unit/test_api*.py"`:
`91 passed, 1 failed` (VER-02).

**Reproducciones de hallazgos.** `v03_concept2.py` (VER-03, VER-04),
`v10_skip_leak.py` (VER-05), `v02_concept.py` (180 corridas sin falsos positivos),
`v04_shortcut.py` (SCI-05), `v05_time.py` (SCI-01/02), `v06_inf.py` (SCI-07),
`v07_perf.py` (rendimiento), `v08_raw.py` (sockets crudos contra la API), `v09_spool.py`
(`kill` a mitad de una subida). El recorrido del panel (`e2e.mjs`, `e2e_csp.mjs`,
`e2e_blob.mjs`) maneja Chrome por el protocolo de depuración contra el compose de
producción local (`VIGIA_DOMAIN=localhost`).

**Salidas clave.**

```
rueda en venv limpio -> ModuleNotFoundError: No module named 'click'   (cli.py:11)
issubclass(typer.BadParameter, click.ClickException) -> False
VER-03  lote de una clase:  critical en 5/6 semillas (caida 0,30 a 0,33)
VER-04  referencia x4:      high en 6/6 semillas (caida 0,13 a 0,20)
misma distribucion, 180 corridas: 0 falsos positivos
SCI-05  ruido continuo independiente, 80 corridas: 0 hallazgos
rendimiento 1 M filas: main 187 s / 2,85 GiB ; despliegue-1.0 185 s / 2,49 GiB
```

**Qué no pude verificar.** `release.yml` (solo corre con un tag), el sdist, el
despliegue en un servidor real y con un dominio real, una auditoría de datos reales
(los pesados no se descargan en esta tarea), y la rama de Windows de los tests del job
`test` en CI (se cancelaron).

---

## 8. Estado del cierre

Rama `despliegue-1.0`, con commits encima de `efc13aa` (`git log --oneline efc13aa..despliegue-1.0`).
Alcance: los hallazgos `VER-01` a `VER-09` y lo que el plan de cierre pidió decir sin rodeos
(SEC-07 y el problema 5). Nada del bloque "después", ni el tope de tiempo por trabajo, ni
`sessionStorage`, ni los problemas 6 y 7.

Verificación final (06/10/2026):

- **Windows:** `pytest -q --cov=src` → **428 passed**, cobertura **93 %**; `ruff check`,
  `ruff format --check` y `mypy src` limpios.
- **Linux, en un contenedor `python:3.12-slim`** con `pip install -e '.[dev,ml,parquet,api]'`
  (más `libgomp1`, que LightGBM necesita y la imagen base no trae) y un `TMPDIR` propio:
  **428 passed**. Antes de la corrección de VER-02, los tests de la API daban allí
  `1 failed, 91 passed` (el mismo test que rompió el CI).
- **Rueda sin extras en un venv limpio** (el mismo paso que ahora está en `ci.yml` y
  `release.yml`, extraído del YAML y corrido tal cual): `vigia version`, `vigia checks` y
  `vigia audit` funcionan, y `click` no está instalado. `actionlint` limpio sobre los dos
  workflows.
- Cada commit se probó con la suite de su área; la suite completa corrió sobre el árbol
  final, no sobre cada commit intermedio.

| ID | Estado | Commit | Test |
|---|---|---|---|
| VER-02 | corregido | `5435ee4` | fixture `autouse` en `tests/conftest.py` (`storage.reset_uploads`); los dos tests que afirmaban `== []` comparan su propio id y el reloj falso parte de 10. Falla antes en Linux (`1 failed, 91 passed`), pasa después (92) |
| VER-01 | corregido | `056adf6`, `1469306` | `test_la_cli_solo_importa_dependencias_del_nucleo` (fallaba con `{'click'}`) y `test_un_error_de_uso_de_typer_dentro_de_un_comando_no_es_un_defecto` (daba 3); job `wheel` en `ci.yml` y paso en `release.yml` |
| VER-03, VER-04 | corregido | `5859e11` | 7 tests en `test_drift.py` (lote de una clase, duplicados ×4, deriva real en una clase, lote igual a la referencia, ninguna clase con 30 filas); el concepto invertido sigue dando crítico |
| VER-09 | corregido (decisión de Joshua: valor fijo y aviso) | `cd8eedb` | `test_api_config.py` (700 por defecto, aviso con 2 GiB, sin aviso con 6 GiB o sin dato, warning en el arranque) |
| VER-05 | corregido | `dc17524` | `test_api_errores.py`: el `fit` roto va a `errors` y no a `skipped`, sin el texto y con semáforo rojo; los motivos de salto se limpian; un test estático prohíbe `{exc}` dentro de un `CheckSkipped` |
| VER-06, VER-07 | corregido | `d430270` | `test_cli_con_errores_y_sin_hallazgos_no_dice_sin_hallazgos_bajo_un_semaforo_rojo`, `test_la_documentacion_cuenta_los_checks_que_hay` |
| VER-08, SEC-07, problema 5 | corregido (documentación) | `9a40bd7` | documentación |

### Calibración de `drift.concept`

Script fuera del repo (`cal_concept.py`, en el directorio temporal de la sesión). Dos
generadoras con clases separadas en distintas direcciones; la deriva real mueve a las clases
de ataque hacia la zona normal.

**Sin deriva: 108 corridas, 0 falsos positivos (13 saltos por pocas filas).** Combinan
n de 200, 1.000, 5.000 y 20.000; desbalanceo 50/50, 80/20 y 96/4; 2, 3 y 5 clases;
duplicados ×1 a ×4 en la referencia; y lotes con todas las clases, con una sola o con dos.
El script de reproducción del plan da `sin hallazgo` en las tres columnas de las 4 semillas
(la semilla 3 con un lote de solo ataques daba alto con el umbral de 3 errores estándar:
por eso es 4).

**Sensibilidad, 6 sorteos por celda** (cuánto se corre el ataque hacia la zona normal, como
fracción de su separación):

| Corrimiento | Lote completo (n 1.000 a 5.000, ataque 4 % a 20 %) | Lote de solo ataques |
|---|---|---|
| 20 % | 0 a 3 de 6 (alta) | 6 de 6 (alta) |
| 35 % | 6 de 6 (alta) | 6 de 6 (alta o crítica) |
| 50 % | 6 de 6 (alta) | 6 de 6 (crítica) |
| 75 % | 6 de 6 (crítica; 3 alta y 3 crítica con ataque 4 %) | 6 de 6 (crítica) |
| 100 % | 6 de 6 (crítica) | 6 de 6 (crítica) |

Los umbrales de 0,10 y 0,25 **no cambian**. Lo que se agregó es la condición de que la caída
supere 4 errores estándar de muestreo; no mueve ninguna celda de la tabla.

### Lo que sigue abierto después del cierre

- Se puede empujar para que el CI confirme: las suites pasan en Windows y en Linux. El
  workflow `wheel` y el paso de `release.yml` no se pudieron ejecutar fuera de GitHub.
- Sin cambios y fuera de esta tanda: el tope de tiempo por trabajo, `sessionStorage` para la
  clave del panel, los problemas 6 y 7 de la sección 9 de `AUDITORIA-1.0.md`, la re-medición
  con datos reales y el bloque "después".
- **Observación nueva, sin arreglar:** los `except Exception` que quedan en otros checks
  convierten un fallo en un salto sin pasar por el texto de la excepción; un test estático
  ahora lo impide solo para `CheckSkipped(...{exc}...)`. No revisé si otros caminos (por
  ejemplo `ImportError` de dependencias opcionales) también merecerían ir a `errors`.
