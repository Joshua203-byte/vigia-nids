# Cierre de Vigía 1.0: corregir lo que encontró la verificación

## Tu rol

Sos el ingeniero que cierra los últimos bloqueantes antes de mergear y
taggear `vigia-nids` 1.0.0. Hubo una auditoría (`AUDITORIA-1.0.md`), dos tandas
de correcciones (secciones 8 y 9 de ese archivo) y una verificación
(`VERIFICACION-1.0.md`). Los dos archivos están en la raíz del repo `Data/`.
Leé `VERIFICACION-1.0.md` completo antes de tocar nada: es la fuente de verdad
de esta tanda.

Es la última tanda antes de algo irreversible. Cambios mínimos y precisos, en
el estilo del código existente. Para `drift.concept`, la pregunta que manda
es: **¿puede este check avisar "crítico" cuando la relación entre
características y etiqueta no cambió, o callarse cuando sí cambió?** Las dos
cosas son fallas.

---

## Estado de partida (verificado el 06/10/2026 por una sesión que no escribió el código)

- Rama `despliegue-1.0` (`efc13aa`), ya empujada a `origin`. Debajo está
  `auditoria-1.0`, sin mergear en `main`. Hay 411 tests que pasan en Windows.
- Reproduje por mi cuenta los cuatro bloqueantes, y los cuatro son reales:
  - **VER-01:** con la rueda instalada en un venv limpio, `vigia version` falla
    con `ModuleNotFoundError: No module named 'click'`. `typer` 0.27.2 ya no
    depende de `click` (`requires`: shellingham, rich, annotated-doc,
    colorama), y `cli.py:11` lo importa para la guarda de `cli.py:135`.
  - **VER-02:** el CI (`gh run view 37394171824 --log-failed`) falla solo en
    `test_api_trabajos.py::test_un_dataset_en_la_cola_no_caduca_por_ttl_de_subida`,
    con `assert ['120bfc93f6e...'] == []`. El id purgado no es de ese test: es
    una subida que dejó otro test, con la hora real de `time.monotonic()`.
  - **VER-03 y VER-04:** los reproduje con el script de abajo. El control (dos
    muestras de la misma distribución) no da nada en 4 de 4 semillas. Lote
    filtrado a `attack`: alto en 3 semillas y crítico en 1. Referencia con
    cada fila repetida 4 veces: alto en 4 de 4. Con clases menos separadas,
    los duplicados llegan a crítico (caída 0,337). Además inflan la exactitud
    de la referencia lo justo para **pasar el filtro `MIN_SKILL`**, que sin
    duplicados frena el check.
- Causas, leídas en `drift/checks.py`, `ConceptDriftCheck.run`:
  - **VER-03:** `balanced_accuracy_score(y_act, pred_act)` sobre un lote con
    una sola clase es el recall de esa clase. Se compara contra `en_ref`, que
    promedia todas las clases.
  - **VER-04:** `cross_val_predict(modelo, x_ref, y_ref, cv=3)` reparte las
    copias de una misma fila entre entrenamiento y prueba.

Script de reproducción (correlo antes y después de corregir):

```python
import numpy as np, polars as pl
from vigia.core.context import AuditContext
from vigia.core.engine import run_audit

def gen(n, seed, p_att=0.04):
    r = np.random.default_rng(seed)
    y = np.where(r.random(n) < p_att, "attack", "benign")
    x1 = r.normal(0, 1, n) + (y == "attack") * 2.0
    x2 = r.normal(0, 1, n) + (y == "attack") * 1.8
    return pl.DataFrame({"x1": x1, "x2": x2, "x3": r.normal(0, 1, n), "Label": y})

def concept(ref, cur, seed):
    ctx = AuditContext(df=cur, label_col="Label", seed=seed); ctx.reference = ref
    rep = run_audit(ctx, checks="drift.concept", module="drift")
    return [(f.severity, round(f.metric["caida"], 3)) for f in rep.findings] \
        or rep.skipped.get("drift.concept", "sin hallazgo")

for s in range(4):
    ref, cur = gen(6000, s), gen(6000, 100 + s)
    print(s, concept(ref, cur, s),
          concept(ref, cur.filter(pl.col("Label") == "attack"), s),
          concept(pl.concat([gen(1500, s)] * 4), cur, s))
```

- Convenciones:
  - Todo en español rioplatense, con voseo: código, docstrings, mensajes,
    tests y commits.
  - Los docstrings explican el porqué y citan el hallazgo
    (`VERIFICACION-1.0.md, VER-xx`).
  - El texto de `src/` cabe en cp1252.
  - Línea máxima de 100 caracteres.
  - Commits según el skill `commits-auditables`: uno por acción, con el
    porqué, y la suite verde en cada uno.

---

## Reglas

1. Seguí en la rama `despliegue-1.0`, con commits encima. **No** hagas push,
   tag, merge ni rebase, y no publiques nada. El push lo decide Joshua.
2. Test primero: cada test nuevo tiene que fallar en el código actual por el
   motivo correcto, y recién ahí corregís.
3. Después de cada corrección: `pytest -q`, `ruff check src tests`,
   `ruff format --check src tests` y `mypy src`.
4. **Linux en local:** como no hay push, la suite completa tiene que pasar
   también en Linux antes de terminar, dentro de un contenedor:
   `docker run --rm -v "<repo>/vigia:/src" -w /src python:3.12-slim sh -c "pip install -q -e '.[dev,ml,parquet,api]' && pytest -q"`.
   Usá un `TMPDIR` propio por corrida. Si Docker Desktop está apagado, avisá y
   no des esto por verificado.
5. Las decisiones marcadas con ⚠ las toma Joshua. Preguntá con opciones y una
   recomendación, y seguí con otro ítem mientras tanto.
6. No amplíes el alcance. Lo nuevo que encuentres va al resumen.

---

## Correcciones, en este orden

### 1. VER-02: el test frágil (desbloquea el CI)
- Una fixture `autouse` en los tests de la API que vacíe el registro de
  subidas (y lo que haga falta del estado global de `storage`/`jobs`) entre
  tests.
- El test compara solo su propio id (`assert b not in purgadas`) y el reloj
  falso parte de un valor chico, para que el resultado no dependa del tiempo
  desde que arrancó la máquina.
- Para probar que el test falla antes de la corrección, correlo en el
  contenedor Linux: en Windows pasa.

### 2. VER-01: la CLI sin `click`
- Sacá `import click`. En `_guarded`, dejá pasar `typer.Exit`, `typer.Abort`
  y los errores de uso de Typer sin nombrar `click`: probá qué expone
  `typer` 0.27 (¿`typer.BadParameter`, `typer._click`?) y elegí lo que
  funcione también con `typer>=0.12`.
- Revisá si algún otro archivo de `src/` importa algo que solo llega por un
  extra (`grep -rn "^import\|^from" src/` contra las dependencias del
  núcleo).
- Fijá un techo razonable a `typer` en `pyproject.toml` si lo justificás.
- **CI y release:** un job (o un paso) que construya la rueda, la instale
  **sin extras** en un venv limpio y corra `vigia version`, `vigia checks` y
  `vigia audit` sobre un CSV sintético chico. El mismo paso va en
  `release.yml`, antes de publicar. Reusá los SHA de actions que ya están
  fijados.
- Test: el que mejor puedas armar sin red. Como mínimo, uno que verifique
  que `vigia.cli` no importa módulos que no estén en las dependencias del
  núcleo. La prueba de verdad es el paso de CI.

### 3. VER-03 y VER-04: `drift.concept`
- **VER-03:** compará cosas comparables. Recomendación: restringí la
  comparación a las clases presentes en el lote con un mínimo de filas, y
  compará el recall de esas clases en la referencia (validación cruzada)
  contra su recall en el lote. Así un lote de una sola clase **sí** se puede
  evaluar, porque es justo el caso "llegan ataques que el modelo ya no
  reconoce", y no hace falta saltarlo. Si ninguna clase llega al mínimo, se
  salta con un motivo claro. Actualizá la métrica, el título y los ejemplos
  del hallazgo para que digan qué clases se compararon.
- **VER-04:** que las copias de una misma fila no queden repartidas entre los
  pliegues de la validación cruzada. Recomendación: `GroupKFold` (o
  `StratifiedGroupKFold`) con el hash de fila como grupo. Deduplicar cambia lo
  que se entrena y conviene menos. El filtro `MIN_SKILL` tiene que evaluarse
  sobre la exactitud corregida.
- Pensá el caso inverso: filas del lote idénticas a filas de la referencia
  inflan `pred_act` y pueden **ocultar** deriva real. Si es barato, excluilas
  de la evaluación del lote (o reportá cuántas hay). Si no, dejalo anotado.
- Tests:
  - lote filtrado a una clase de la misma distribución → sin hallazgo;
  - referencia con duplicados ×4, misma distribución → sin hallazgo;
  - el concepto invertido de la primera tanda sigue dando crítico;
  - un lote de una sola clase **con** deriva real en esa clase (por ejemplo,
    ataques que se corren hacia la zona benigna) → hallazgo.
- **Calibración:** repetí la medición de la verificación con la corrección
  hecha. Al menos 100 corridas con semillas distintas sin deriva, variando n
  (200 a 20.000), desbalanceo (50/50 a 96/4), cantidad de clases (2 a 5),
  duplicados (×1 a ×4) y lotes de una o varias clases. Contá los falsos
  positivos, que tienen que ser 0 o casi 0. Medí también la sensibilidad con
  deriva real en varios grados. Dejá el script fuera del repo y la tabla de
  resultados en el resumen. Si los umbrales de 0,10 y 0,25 ya no sirven,
  ⚠ proponé valores nuevos con los números en la mano y preguntá.
- Corregí `docs/DERIVA.md` para que describa el método nuevo.

### 4. VER-05: motivos de salto con texto de excepción
- Un fallo de entrenamiento **no** es "no aplica": que se lance como error
  (va a `errors`, semáforo rojo, código 3), coherente con COR-05. Aplica a
  `label_noise.py:168,197`, `drift/checks.py:355,501` y
  `poison/detectors.py:177`. Revisá cada uno: si alguno es de verdad un "no
  aplica" (por ejemplo, datos insuficientes detectados por la propia
  excepción), dejalo como salto pero sin `{exc}`.
- `_anonymize` en la API sanea también `skipped` como defensa en profundidad.
- Test: el de `test_api_errores.py` adaptado a un check que antes se saltaba
  con `{exc}`.

### 5. VER-06, VER-07, VER-08: detalles
- **VER-06:** con `errors` y sin hallazgos, la CLI no imprime "sin hallazgos"
  en verde.
- **VER-07:** el registro tiene 25 checks (16 + 4 + 5). Corregí `README.md`,
  `docs/PLAN.md` y `CHANGELOG.md`, y agregá un test que compare el número de
  la documentación con `len(all_checks(None))`, para que no se vuelva a
  desfasar.
- **VER-08:** en `DESPLIEGUE.md`, separá "por defecto en el código" de "en el
  compose de producción".

### 6. VER-09: topes contra el pico de memoria
- ⚠ **Decisión:** ¿derivar `VIGIA_MAX_EXPANDED_MB` de la memoria disponible con
  el factor medido (≈8×), o fijarlo en un valor conservador (~700 MB) y
  documentar cómo subirlo? Recomendación: valor fijo conservador más una
  advertencia al arrancar si `MAX_EXPANDED_MB × 8` supera la memoria del
  contenedor (leela de cgroups si está disponible). Es simple y se puede
  explicar.

### 7. SEC-07 y el problema 5: decirlo sin rodeos
- `DESPLIEGUE.md` explica, en un apartado de límites de seguridad:
  - no hay aislamiento entre clientes: quien tiene la clave y conoce un
    `job_id` lee el reporte, con filas e IPs reales;
  - no hay tope de tiempo por trabajo: un cliente con la clave puede tener el
    servicio ocupado horas.
  Para los dos casos, el criterio es dar la clave solo a gente de confianza.
- ⚠ No implementes el tope de tiempo (requiere correr los trabajos en un
  proceso aparte). Anotalo como pendiente posterior a la 1.0.

### 8. Documentación y CHANGELOG
- Todo lo nuevo va bajo `[Unreleased]`.
- Actualizá el número de tests en `PLAN.md`.
- Agregá al final de `VERIFICACION-1.0.md` una sección **"8. Estado del
  cierre"** con la tabla `ID | estado | commit | test`.

---

## Fuera de alcance

- El tope de tiempo por trabajo, `sessionStorage` para la clave del panel y
  los problemas 6 y 7 de la sección 9.
- La re-medición con datos reales (los 2.867 infinitos y `drift.concept` sobre
  CIC-IDS2017).
- El bloque "después" de la auditoría.
- Mergear, numerar la versión y taggear.

---

## Entregable

1. Commits en `despliegue-1.0`, uno por corrección, con la suite verde en
   Windows en cada uno y la suite final verde **también en Linux** (en el
   contenedor).
2. La rueda instalada sin extras en un venv limpio: `vigia version`,
   `checks` y `audit` funcionan.
3. El script de reproducción de arriba da "sin hallazgo" en las tres columnas
   de las 4 semillas, y la tabla de calibración (falsos positivos y
   sensibilidad).
4. En el chat, solo:
   - qué quedó corregido;
   - las decisiones ⚠ pendientes;
   - la tabla de calibración resumida;
   - si se puede empujar para que el CI confirme;
   - `git log --oneline efc13aa..despliegue-1.0`.
