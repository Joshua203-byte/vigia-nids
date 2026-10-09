# Módulo 3 — Monitor de deriva

Avisa cuando el modelo deja de estar al día: el tráfico de hoy ya no se parece
al que se usó para entrenarlo.

```bash
vigia drift lote_de_hoy.parquet --reference datos_de_entrenamiento.parquet
```

**Índice:** [Qué es la deriva](#qué-es-la-deriva) · [Los cinco checks](#los-cinco-checks) ·
[Las métricas](#las-métricas) · [Cómo leer el resultado](#cómo-leer-el-resultado) ·
[En producción](#en-producción) · [Limitaciones](#limitaciones)

---

## Qué es la deriva

**Un dataset puede estar perfecto y aun así haber derivado.** La red cambió,
apareció una aplicación nueva, el atacante cambió de técnica. No es un defecto
de los datos: es que el mundo se movió y el modelo se quedó donde estaba.

Por eso es un módulo aparte y no un check más del auditor: lo que hay que hacer
al respecto —reentrenar— es distinto de corregir un dataset.

| Tipo | Qué cambia | Check |
|---|---|---|
| **Datos** (covariate shift) | La distribución de cada característica | `drift.feature` |
| **Datos** (covariate shift) | La distribución conjunta: los conjuntos se distinguen | `drift.covariate` |
| **Etiquetas** (prior shift) | La proporción de cada clase | `drift.prior` |
| **Concepto** | La relación entre características y etiqueta | `drift.concept` |
| **Esquema** | Columnas nuevas, faltantes o con otro tipo | `drift.schema` |

> Antes de la 1.0.0, `drift.concept` era la validación adversaria que hoy se llama
> `drift.covariate`. No miraba la etiqueta, así que no podía ver deriva de
> concepto: con la misma distribución de características y la etiqueta
> invertida daba verde.

---

## Los cinco checks

### `drift.schema` — mirá este primero

Columnas que aparecen, faltan o cambiaron de tipo.

| Caso | Severidad | Por qué |
|---|---|---|
| Falta una columna | **crítica** | El modelo no puede predecir sin ella |
| Cambió de tipo | alta | Los valores pueden estar mal interpretados |
| Hay una nueva | media | Solo se ignora |

**Va primero a propósito.** Si una columna cambió de unidad o de tipo, el PSI
dirá que hay deriva severa y tendrá razón — pero la causa es el sensor, no la
red. Arreglar eso antes de mirar lo demás evita conclusiones equivocadas.

### `drift.feature` — la distribución cambió

PSI por columna numérica. Reporta las que superan 0,2 (`--psi-threshold`).

El modelo sigue funcionando pero está extrapolando: sus métricas de validación
describen otro tráfico.

**Una columna sola puede ser un sensor; muchas a la vez es que cambió la red.**
Por eso 5 o más columnas derivadas sube la severidad, y el hallazgo lo dice
explícitamente en su descripción.

### `drift.prior` — cambió la mezcla de clases

Divergencia de Jensen-Shannon sobre la distribución de etiquetas.

| Caso | Qué hacer |
|---|---|
| Apareció una clase nueva | Reentrenar; el modelo no puede predecir algo que nunca vio |
| Solo cambió la proporción | Recalibrar el umbral suele alcanzar |

Una campaña masiva de escaneo cambia la proporción de ataques sin que cambie
nada más. El modelo sigue siendo válido; su umbral de decisión y la carga de
alertas que produce, no.

### `drift.covariate` — los conjuntos son distinguibles

Validación adversaria: entrena un clasificador para decidir si una fila viene
de la referencia o del lote nuevo.

- **AUC ≈ 0,5** → no puede distinguirlos. Es lo esperable sin deriva.
- **AUC ≥ 0,75** → son separables. El modelo de producción está viendo un
  tráfico distinto del que aprendió.
- **AUC ≥ 0,9** → crítico.

Ve lo que `drift.feature` no ve: las distribuciones individuales pueden no
haberse movido mucho, pero la combinación sí. El hallazgo lista las columnas
que más aportan a distinguirlos, que son las que más cambiaron. **No mira la
etiqueta:** que los conjuntos no se distingan no dice nada sobre si la
etiqueta sigue significando lo mismo.

### `drift.concept` — cambió la relación con la etiqueta

Entrena un modelo con la referencia y compara, **clase por clase**, cuánto
reconoce dentro de ella (validación cruzada) con cuánto reconoce en el lote. La
cifra que se compara es el recall medio de las clases que están en los dos lados
con al menos 30 filas.

| Caída del recall medio | Severidad |
|---|---|
| < 0,10, o dentro del ruido de muestreo (menos de 3 errores estándar) | Sin hallazgo |
| 0,10 – 0,25 | alta |
| ≥ 0,25 | crítica |

Tres cuidados, cada uno por una falla medida (`VERIFICACION-1.0.md`):

- **Se comparan las mismas clases.** Un lote de una sola clase se puede
  evaluar: es justo el caso "llegan ataques que el modelo ya no reconoce", y se
  compara el recall de esa clase contra su propio recall en la referencia. Antes se
  comparaba la exactitud balanceada de todas las clases contra la de las que traía
  el lote, y un lote de pura clase rara daba crítico sin que nada hubiera cambiado.
- **Las filas repetidas van juntas en la validación cruzada.** Las copias de una
  misma fila (habituales en datos de flujos) no se reparten entre entrenamiento y
  prueba: si no, la referencia parecía "saber" más de lo que sabe y cualquier lote
  nuevo parecía derivar.
- **Las filas del lote que ya están en la referencia se excluyen.** El modelo las
  memorizó y aciertan sin decir nada de la relación con la etiqueta; excluirlas
  evita que oculten una deriva real. La métrica `n_filas_repetidas_excluidas` dice
  cuántas fueron, y si no queda nada con qué comparar el check se salta diciéndolo.

Es la única forma de ver que lo que antes era "ataque" ahora es otra cosa
aunque el tráfico se vea igual. **Necesita la etiqueta en el lote**: sin ella
se salta y lo dice, y el comando no afirma que no haga falta reentrenar. Las
clases que la referencia nunca vio no cuentan como caída: las reporta
`drift.prior` como clases nuevas. Si `drift.covariate` o `drift.feature`
también reportan, parte de la caída puede venir de que el modelo extrapola
sobre tráfico distinto.

---

## Las métricas

Implementadas en `vigia.drift.metrics`, sin dependencias extra.

### PSI (Population Stability Index)

| Valor | Lectura |
|---|---|
| < 0,1 | Sin cambio relevante |
| 0,1 – 0,2 | Moderado, vale la pena mirar |
| > 0,2 | Importante |
| > 0,25 | Conviene reentrenar |

Su virtud sobre una prueba estadística: **los umbrales no dependen del tamaño
del lote**. Un p-valor sobre un millón de filas declara significativo cualquier
cambio.

Los bins se calculan **por cuantil** sobre la referencia. Casi todas las
métricas de red tienen cola larga: con cortes uniformes casi todos los bins
quedarían vacíos y el PSI mediría el ruido de esos bins en vez de la deriva.

### Kolmogorov-Smirnov

Máxima distancia entre las funciones de distribución acumulada, entre 0 y 1.
Se devuelve **el estadístico, no el p-valor**, por la misma razón: sobre
millones de filas lo que importa es el tamaño del efecto.

### Jensen-Shannon

Para las categóricas, donde no hay orden. Simétrica y acotada entre 0 y 1, a
diferencia de KL. Las categorías que solo aparecen de un lado cuentan, que es
justamente lo que hay que detectar.

---

## Cómo leer el resultado

```
Semáforo: ROJO  · 2.000 filas × 5 columnas
critical: 1  high: 1

critical  drift.covariate  Un clasificador distingue los dos conjuntos con AUC 0.999
high      drift.feature    2 característica(s) cambiaron de distribución
```

**El orden de lectura importa:**

1. **`drift.schema`** primero — si el esquema cambió, lo demás puede ser
   consecuencia de eso
2. **`drift.concept`** — si el modelo dejó de acertar, hay que reentrenar
3. **`drift.covariate`** — el AUC resume cuánto cambió el tráfico en total
4. **`drift.feature`** — qué columnas específicas se movieron
5. **`drift.prior`** — si además cambió la mezcla de clases

Solo sin hallazgos **y** sin checks saltados el comando lo dice: *"El lote se
parece a la referencia: no hace falta reentrenar."* Si `drift.concept` se
saltó (por ejemplo, el lote no trae etiqueta), esa frase no aparece.

---

## En producción

### Por lotes

```bash
vigia drift lotes/2026-09-19.parquet \
  --reference datos_entrenamiento.parquet \
  --fail-on high \
  --report deriva/2026-09-19/
```

Sale con código 1 si hay deriva alta o peor, así que sirve en un cron o en CI.

### Desde Python

```python
import vigia
from vigia.core.engine import run_audit
from vigia.io.readers import read_dataset

ctx = vigia.load("lote_nuevo.parquet", label_col="Label")
ctx.reference = read_dataset("referencia.parquet")

report = run_audit(ctx, module="drift")
if report.exceeds("high"):
    alertar("hay que reentrenar", report.to_dict())
```

### Elegir la referencia

La referencia debería ser **los datos con los que se entrenó el modelo en
producción**, no el lote de la semana pasada. Comparar contra el lote anterior
detecta cambios bruscos pero se pierde la deriva lenta: cada semana se parece a
la anterior, y en seis meses el tráfico es otro.

---

## Medido sobre datos reales

Los cinco días de CIC-IDS2017 son una serie temporal genuina: la misma red, la
misma instrumentación, días distintos. El lunes es enteramente benigno.
`benchmarks/cic_deriva_real.py` compara cada día contra él.

| Comparación | Semáforo | AUC | Columnas con PSI alto |
|---|---|---|---|
| Lunes barajado contra sí mismo | **verde** | < 0,75 | 0 |
| Martes vs. lunes | rojo | 0,816 | 16 |
| Miércoles vs. lunes | rojo | 0,801 | 42 |
| Jueves vs. lunes | rojo | 0,757 | 1 |
| Viernes vs. lunes | rojo | 0,840 | 31 |

El control negativo es el que más importa: dos muestras aleatorias del mismo
día no producen ningún hallazgo. Si lo produjeran, todo lo demás sobraría.

La columna AUC es la de `drift.covariate`, que en esa medición se llamaba
`drift.concept`. La tabla se midió antes de que existiera el `drift.concept`
actual y está **pendiente de re-medir**: como el lunes tiene una sola clase,
`drift.concept` se saltaría en todas las filas, así que el control daría gris y
no verde (los hallazgos de `drift.covariate` y `drift.feature` no cambian).

### Una sorpresa: el corte define la comparación

Comparar la **primera mitad** del lunes contra la segunda da AUC 0,873 y 51
columnas derivadas — más deriva que martes contra lunes.

No es un fallo. Los archivos vienen en orden temporal, así que esa comparación
es la mañana del lunes contra la tarde, y el tráfico de oficina cambia entre
una y otra: a la mañana se leen correos, a la tarde se transfieren archivos.

La lección es práctica: **cómo se corta un lote determina qué deriva se ve.**
Un lote de "ayer" que en realidad abarca de las 14:00 a las 14:00 mezcla dos
perfiles distintos y produce deriva que nadie introdujo.

---

## Limitaciones

**No mide el rendimiento real.** Sin etiquetas nuevas, la deriva es una señal
indirecta: dice que el tráfico cambió, no que el modelo esté fallando. Cuando
lleguen etiquetas del SOC, medir el F1 real es mejor evidencia.

**`drift.covariate` y `drift.concept` trabajan sobre una muestra** de hasta
50.000 filas por lado, y necesitan al menos 50 de cada uno.

**Un lote chico da falsos negativos.** Con pocos cientos de filas, el PSI y el
AUC son inestables y la deriva real puede no alcanzar el umbral.

**No es streaming.** El módulo trabaja por lotes. ADWIN, DDM y Kafka están
planificados como P2 en el diseño.
