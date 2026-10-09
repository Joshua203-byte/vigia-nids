# Arquitectura

Cómo está armado Vigía por dentro y por qué. Para quien va a tocar el código.

**Índice:** [El recorrido de una auditoría](#el-recorrido-de-una-auditoría) ·
[Las cinco piezas](#las-cinco-piezas) · [Agregar un check](#agregar-un-check) ·
[Agregar una corrección](#agregar-una-corrección) ·
[Los tres módulos](#los-tres-módulos) · [Decisiones y por qué](#decisiones-y-por-qué)

---

## El recorrido de una auditoría

```
archivo(s)  ──►  read_dataset      CSV, Parquet, Zeek, Suricata EVE, PCAP
                      │
                      ▼
                 detect_column     encuentra label, split, tiempo, IPs, puertos
                      │
                      ▼
                 AuditContext      dataset + qué es cada columna + caché
                      │
                      ▼
                 run_audit         corre cada check aislado
                      │
             ┌────────┴────────┐
             ▼                 ▼
         Finding(s)     skipped / errors   un check que no puede correr (o falla) lo dice
             │                 │
             └────────┬────────┘
                      ▼
                   Report         semáforo, conteos, orden por severidad
                      │
             ┌────────┼────────┐
             ▼        ▼        ▼
          consola   HTML     JSON
```

Y si se corrigen los hallazgos:

```
Report ──► apply_fix ──► FixResult ──► dataset corregido + registro de qué cambió
                                  └──► cuarentena (filas dudosas, nunca borradas)
```

---

## Las cinco piezas

### `core/context.py` — AuditContext

Lo que un check necesita saber: el DataFrame, qué columna es cuál, y los
cálculos caros ya hechos.

Los derivados usan `cached_property`, así que se calculan una vez y se comparten
entre todos los checks de una ejecución:

| Propiedad | Qué es |
|---|---|
| `feature_cols` | Columnas que no son etiqueta, split ni internas (`__*`) |
| `numeric_cols` | Las numéricas de entre esas |
| `declared_roles` | Columnas de tiempo e IP que el usuario declaró (opción o perfil); las solo detectadas por nombre no entran |
| `hash_cols` | `feature_cols` sin los `declared_roles`: lo que define "la misma fila" |
| `row_hash` | Hash por fila sobre `hash_cols` |
| `full_row_hash` | Igual, incluyendo la etiqueta |
| `shared` | Diccionario libre para lo que el contexto no sabe calcular solo |

`require("split_col", "time_col")` lanza `CheckSkipped` si falta alguno. Es la
forma correcta de decir "este check no aplica acá".

`ctx.option(clave, default)` lee configuración del usuario con un valor por
defecto.

### `io/` — los lectores

`read_dataset` despacha por extensión a un lector por formato. Cada uno vive en
su módulo y se importa **dentro** de la función, no arriba: así un `.csv` no
paga el arranque de NFStream, que tarda segundos.

| Módulo | Formato | Lo que cuesta acertar |
|---|---|---|
| `readers.py` | CSV, Parquet, despacho | Reintento en cp1252 |
| `zeek.py` | TSV con cabecera, JSON Lines | El separador escapado y los CRLF |
| `suricata.py` | EVE JSON | Filtrar por `event_type`, aplanar structs |
| `pcap.py` | PCAP vía NFStream | Dependencia opcional pesada |

Dos formatos son ambiguos por extensión y se deciden mirando el contenido: un
`.log` puede ser TSV o JSON, y un `.json` puede ser EVE o un JSON Lines
cualquiera.

**El bug más caro de esta parte fue un `\r`.** Zeek declara su separador como
`#separator \x09`, y con tab explícito el retorno de carro no es delimitador:
en cualquier log copiado a Windows la última columna pasaba a llamarse
`orig_bytes\r` y no matcheaba con nada. Los CRLF se normalizan al leer.

### `core/findings.py` — Finding y Report

Un `Finding` es la unidad de salida. Sin métrica, ejemplos y recomendación no es
un hallazgo, es una queja (principio 4 del diseño).

```python
Finding(
    check_id="leak.temporal",
    severity="critical",  # critical | high | medium | low | info
    title="...",  # una línea, con el número adentro
    description="...",  # qué pasa y por qué importa
    metric={"overlap_ratio": 0.93},
    affected_rows=1200,
    examples=[...],  # se recortan a 10
    recommendation="...",  # qué hacer
    auto_fix="temporal_split",
    row_indices=[3, 7, 11],  # opcional: qué filas exactamente
    row_scores=[0.9, 0.8, 0.4],  # opcional: cuánto sospecha de cada una
)
```

`row_indices` y `row_scores` **no van al reporte**: son para que una corrección
actúe sobre las filas exactas sin repetir el cómputo, y para que el módulo de
envenenamiento combine varios detectores. En un dataset grande serían miles de
números que nadie lee.

El `Report` calcula el semáforo:

| Color | Significa |
|---|---|
| rojo | Hay hallazgos críticos o altos, **o algún check falló por un error interno** |
| amarillo | Hay hallazgos medios o bajos |
| verde | Sin hallazgos **y** todos los checks corrieron |
| **gris** | Sin hallazgos, pero algunos checks no pudieron correr |

Un check que falló por un bug no puede dar verde ni gris: el reporte está
incompleto por un defecto del programa, y gris se lee como "faltó una columna".

### `core/registry.py` — el registro

Cada check es un plugin. Se registra con un decorador y queda disponible:

```python
@register
class MiCheck:
    id = "categoria.mi_check"
    name = "Qué revisa"
    category = "validity"
    applies_to = {"flows"}
    module = "auditor"  # opcional: auditor (default) | poison | drift

    def run(self, ctx: AuditContext) -> list[Finding]: ...
```

`select(spec, module)` resuelve `"all"`, ids exactos o prefijos de categoría
(`"leak"` toma `leak.*`), siempre dentro de un módulo.

Un check que emite hallazgos bajo más de un id lo declara con
`also_emits = ("dup.class_ratio",)`, para que esos ids se puedan pedir y
aparezcan en el catálogo.

### `core/engine.py` — el motor

Corre cada check **aislado**:

- `CheckSkipped` → va a `report.skipped` con el motivo, el resto sigue. Es una
  decisión de diseño ("falta la columna de split"): dice algo del dataset.
- Cualquier otra excepción → va a `report.errors`, **aparte**, como
  `"Tipo: mensaje"`, con el traceback en el log. Es un bug: no dice nada del
  dataset, y mezclarlo con los saltos hacía que un crash se leyera como una
  columna que faltaba.

Un check con un bug nunca tumba la auditoría entera. La CLI sale con código 3
si hubo errores (ver [`USO.md`](USO.md#línea-de-comandos)).

### `fixes/` — las correcciones

Tres reglas que valen para todas:

1. **No modifican nada en el lugar.** Devuelven un DataFrame nuevo.
2. **Nunca borran filas dudosas.** `quarantine_noise` las aparta.
3. **Dejan constancia.** El `FixResult` dice qué cambió y cuánto.

---

## Agregar un check

Un archivo en `src/vigia/checks/`, una clase, cuatro atributos y un método:

```python
from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register


@register
class PuertosEfimeros:
    id = "shortcut.ephemeral_port"
    name = "Puerto de origen efímero como característica"
    category = "shortcuts"
    applies_to = {"flows"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("src_port_col")  # se salta si falta
        assert ctx.src_port_col is not None  # para mypy

        s = ctx.df.get_column(ctx.src_port_col)
        n = int((s >= 32768).sum())
        if n == 0:
            return []

        return [Finding(...)]
```

Después:

1. Importarlo en `checks/__init__.py` para que el registro lo encuentre.
2. Escribir los tests en `tests/unit/`, incluyendo **el caso donde no debe
   reportar nada**. El control de falsos positivos importa tanto como la
   detección.
3. Documentarlo en [`CHECKS.md`](CHECKS.md).

**Lo que más cuesta acertar** no es detectar el problema: es no reportarlo
cuando no está. Cuatro falsos positivos reales que aparecieron en este proyecto:

- Una columna continua da exactitud 1,0 trivialmente en el check de atajos
- `-1` es un centinela válido en las ventanas TCP, no un valor imposible
- cleanlab marca como ruido todo lo que el modelo no predice, aunque no haya
  ruido
- Un límite que se aplica valor por valor no acota el total: `poison.trigger`
  descartaba cada valor individualmente y terminaba marcando el 74 % de un
  dataset limpio

### Un fixture sintético no alcanza

El último de esos cuatro **pasaba todos los tests**. Los fixtures generados
tienen pocas columnas, pocos valores distintos y clases equilibradas; los
datasets reales tienen decenas de columnas correlacionadas, colas largas y
clases con relación 40:1.

Reproducir ese defecto en un test exigió las tres condiciones a la vez: 30.000
filas para superar los mínimos de soporte, varias columnas de conteo con cola
larga, y medias que difieren por clase. Con cualquiera de las tres ausente el
test pasaba igual **con y sin la corrección**, que es la peor clase de test de
regresión: da confianza sin verificar nada.

Vale la pena verificar que un test de regresión falla al revertir la corrección.
Es rápido y evita justo ese caso.

## Agregar una corrección

```python
from vigia.fixes.base import FixNotApplicable, FixResult, _result, register_fix


@register_fix("mi_correccion")
def mi_correccion(ctx: AuditContext) -> FixResult:
    """Una línea que explique qué hace; aparece en `vigia fixes`."""
    if nada_que_hacer:
        raise FixNotApplicable("por qué no aplica")

    df = ctx.df.filter(...)  # nunca modificar ctx.df
    return _result(ctx, "mi_correccion", df, "resumen de lo que cambió", {...})
```

El id tiene que coincidir con el `auto_fix` que nombran los hallazgos.

---

## Los tres módulos

| Módulo | Paquete | Comando | Checks | Documento |
|---|---|---|---|---|
| 1. Auditor | `vigia.checks` | `vigia audit` | 17 | [CHECKS.md](CHECKS.md) |
| 2. Envenenamiento | `vigia.poison` | `vigia poison` | 4 | [ENVENENAMIENTO.md](ENVENENAMIENTO.md) |
| 3. Deriva | `vigia.drift` | `vigia drift` | 5 | [DERIVA.md](DERIVA.md) |

Los checks declaran a cuál pertenecen con `module`. `vigia audit` corre solo los
del auditor: los otros necesitan cosas que una auditoría normal no tiene, y
correrlos ahí solo llenaría el reporte de checks saltados por motivos que no
dicen nada sobre el dataset.

```python
run_audit(ctx, module="poison")  # solo los detectores de envenenamiento
all_checks(None)  # todos, de los tres módulos
```

Tres piezas del núcleo existen para los módulos 2 y 3:

| Pieza | Para qué | Quién la usa |
|---|---|---|
| `ctx.reference` | El dataset contra el cual comparar | Los cinco checks de deriva |
| `ctx.shared` | Caché de resultados caros compartidos | La matriz de características de los detectores |
| `row_scores` | Puntaje de sospecha por fila | `combine_scores` para unir detectores |

**La diferencia de fondo entre los módulos** no es técnica sino de qué se hace
con el resultado:

- Un hallazgo del auditor se corrige: el dataset está mal.
- Un hallazgo de envenenamiento se investiga: alguien pudo haberlo insertado, y
  un puntaje alto es motivo para mirar, no para borrar.
- Un hallazgo de deriva se atiende reentrenando: el dataset puede estar
  perfecto y aun así el mundo cambió.

---

## Decisiones y por qué

**Polars y no pandas.** 2,8 millones de filas en 95 segundos sin agotar la
memoria. La API de expresiones también hace más difícil escribir un filtro que
silenciosamente no filtra nada.

**Hash y no comparación.** Detectar duplicados comparando filas es cuadrático.
Con `hash_rows()` nativo de Polars es una pasada, sin pagar el costo de
materializar cada fila como texto en Python (~0,3 GB extra por millón de
filas con la implementación anterior basada en xxhash). Los valores del hash
solo se comparan entre sí dentro de una misma ejecución, nunca se persisten
ni se comparan entre versiones de Vigía.

**`group_by` y no un modelo por columna.** El check de atajos calcula la
exactitud balanceada de la regla "predecir la clase mayoritaria de cada valor".
Es el techo de lo que un árbol sin profundidad limitada logra con esa columna
sola, y corre sobre millones de filas.

**Saltarse antes que adivinar.** Si falta la columna de tiempo, `leak.temporal`
no corre. La alternativa —correr sobre la columna que más se le parezca— produce
un número que se ve como un resultado. Ese bug existió: `detect_column(df,
"time")` devolvía `pkts_fwd` porque `"ts"` matcheaba dentro de `"pktsfwd"`.

**Escapado con comillas en el HTML.** El contenido viene de tráfico de red
capturado, que es entrada no confiable por definición, y el reporte está pensado
para compartirse.

**Todo el texto en cp1252.** La consola de Windows usa esa codificación por
defecto; un carácter fuera de ella hace fallar el comando después de haber hecho
todo el trabajo. Sin flechas `→`, sin `∞`, sin `↳`.

---

## Qué es API pública y qué no (docs/PLAN.md, fase 4.4)

Vigía sigue [Versionado Semántico](https://semver.org/lang/es/): un cambio
incompatible en algo de esta lista sube la versión mayor.

**Estable — un cambio incompatible es un breaking change:**

- `vigia.load()` y `vigia.audit()` (`src/vigia/__init__.py`): firma y valores
  de retorno.
- La forma del JSON que produce `Report.to_dict()` / `Report.to_json()`:
  las claves de `schema_version`, `dataset`, `run`, `summary` (con `n_skipped`
  y `n_errors`), `skipped` y `errors`, y los campos de cada `Finding`
  (`check_id`, `severity`, `title`, `description`, `metric`, `affected_rows`,
  `examples`, `recommendation`, `auto_fix`). Agregar una clave nueva no es
  incompatible; quitar o renombrar una sí. `schema_version` (hoy `"1"`) sube
  solo con un cambio incompatible, y es lo que permite a quien consume el JSON
  en CI detectarlo. `errors` y `schema_version` se agregaron antes de la 1.0
  justamente para no pagar una versión mayor después.
  `row_indices`/`row_scores` son explícitamente internos: `Finding.to_dict()`
  los excluye a propósito y no forman parte de este contrato.
- Los códigos de salida de la CLI (0/1/2/3) y el significado de `--fail-on`.
  Ver [`USO.md`](USO.md#línea-de-comandos).
  - Comandos y opciones documentados de `vigia` en `USO.md`.
  - Los endpoints de la API bajo `/api/v1` documentados en
    [`USO.md`](USO.md#api-rest): rutas, forma del body de request, y forma de
    `JobStatusResponse`. La API todavía no tiene un número de versión propio
    separado del paquete (el campo `version` de `FastAPI(...)` es fijo en
    `"1"`); cuando lo tenga, esta sección se actualiza para reflejar cómo se
    versiona por separado del paquete Python.
  - Los ids de check (`dup.exact`, `leak.host`, etc.) y de corrección
    (`drop_duplicates`, etc.): son la forma en que `--checks` y `--apply` los
    referencian, y el panel web (`web/src/pages/Fix.tsx`) los usa para
    describir qué hace cada corrección.

**Inestable — puede cambiar en cualquier versión menor o de parche:**

- Los valores de `row_hash` / `full_row_hash` (`src/vigia/core/hashing.py`):
  ya cambiaron una vez al migrar de xxhash a `hash_rows()` nativo, y pueden
  volver a cambiar. Nunca se persisten ni se comparan entre ejecuciones.
- El texto exacto de `title`, `description` y `recommendation` de un
  `Finding`: son prosa para que la lea una persona, no una API para parsear.
  Si algo del contenido de un hallazgo necesita leerse por programa, tiene
  que estar en `metric` o `examples`, no en el texto.
- Cualquier cosa bajo `vigia.core.*`, `vigia.checks.*`, `vigia.drift.*`,
  `vigia.poison.*`, `vigia.fixes.*`, `vigia.api.*` que no esté re-exportada
  desde `vigia/__init__.py` o documentada en `USO.md`. Son detalles de
  implementación aunque Python no impida importarlos directamente.
- El HTML/CSS exacto del reporte (`src/vigia/report/render.py`) y del panel
  web (`web/`): pueden rediseñarse sin que eso sea un cambio incompatible,
  siempre que el JSON subyacente no cambie.

---

## Desarrollo

```bash
pip install -e ".[dev,ml]"

pytest                  # 428 tests
ruff check src tests    # lint
ruff format src tests   # formato
mypy src                # tipos
```

Los benchmarks contra datasets reales están en
[`benchmarks/RESULTADOS.md`](../benchmarks/RESULTADOS.md).
