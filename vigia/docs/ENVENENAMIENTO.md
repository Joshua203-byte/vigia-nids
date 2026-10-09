# Módulo 2 — Detección de envenenamiento

Busca registros insertados a propósito para manipular el modelo.

```bash
vigia poison data/flows.parquet
```

**Índice:** [Qué busca](#qué-busca) · [Los cuatro detectores](#los-cuatro-detectores) ·
[Por qué se combinan](#por-qué-se-combinan) · [El simulador](#el-simulador) ·
[Qué tan bien funciona](#qué-tan-bien-funciona) · [Limitaciones](#limitaciones)

---

## Qué busca

| Tipo | Cómo se ve | Ejemplo |
|---|---|---|
| **Cambio de etiqueta** | Filas de ataque marcadas como benignas | Alguien con acceso al pipeline de etiquetado marca su propio tráfico como normal |
| **Puerta trasera** | Un valor fijo asociado siempre a "benigno" | Un tamaño de ventana TCP concreto que el modelo aprende a ignorar |
| **Inyección de datos** | Filas fabricadas que se parecen al ataque | Tráfico sintético enviado a una red trampa que alimenta el dataset |

La diferencia con el auditor: un defecto de calidad afecta a una columna
entera, un envenenamiento a un puñado de filas concretas. Por eso este módulo
puntúa **por fila**.

---

## Los cuatro detectores

### `poison.loss`

Entrena un modelo con validación cruzada y mira qué probabilidad le asigna a la
etiqueta que cada fila declara. Una fila envenenada suele recibir probabilidad
baja: el resto del dataset dice otra cosa.

Es el más general y el que más se equivoca, porque una fila genuinamente rara
también recibe probabilidad baja. Reporta el 1 % peor, siempre. **Su valor está
en coincidir con otro detector, no en su lista por separado.**

### `poison.knn`

Mira los 10 flujos más parecidos a cada fila. Si al menos el 80 % tiene otra
etiqueta, la marca.

Es el mejor para cambios de etiqueta: la fila envenenada queda rodeada de
vecinos que la contradicen. Más preciso que `poison.loss` porque mira la
vecindad local en vez del modelo global, así que sufre menos con las clases
raras.

### `poison.cluster` — fuera del puntaje combinado

Busca grupos pequeños y mucho más compactos que el resto de su clase, usando
DBSCAN por clase. La idea: las filas inyectadas en un mismo ataque salen del
mismo generador, así que se parecen demasiado entre sí.

> **Sobre CIC-IDS2017 da precisión y recall 0,000** en los dos ataques que fue
> diseñado para detectar, mientras marca entre 1.755 y 2.171 filas de 30.000.
> Su `eps` se fija en el percentil 10 de la distancia entre vecinos, que sobre
> tráfico real solo agrupa flujos casi idénticos —repeticiones normales del
> mismo servicio— y no las filas inyectadas, que llevan jitter. Se probaron los
> percentiles 25, 50, 75 y 90: con 90 el recall sube a 0,495 pero marcando
> 13.655 filas, precisión 0,022. **No hay punto de operación útil.**
>
> Pesa **cero** en el puntaje combinado desde entonces, y queda excluido del
> conteo de coincidencias: con solo el peso en cero seguiría subiendo la
> bonificación de filas que señaló un detector solo.

Sigue registrado y publicando su hallazgo, porque sobre datasets sintéticos o
más limpios sí encuentra inyecciones. Su lista se lee aparte, no en el ranking.

### `poison.trigger`

Busca valores que son **raros en el dataset entero** pero **concentrados en una
clase**.

Una puerta trasera necesita un patrón que el modelo asocie con "benigno", y eso
deja esa huella exacta.

> **Las dos condiciones importan.** Solo con la concentración, el detector marca
> las características legítimas del ataque: el tamaño de paquete típico de un
> DDoS también está concentrado en su clase. En pruebas, eso daba lift de 258 y
> el 100 % de las filas de un dataset limpio reportadas. Lo que distingue a un
> trigger es que además **no debería estar ahí**: es raro en todo lo demás.

Y hay una tercera condición, que solo apareció al medir sobre datos reales: una
columna puede aportar **como mucho tres valores**. Los otros límites se aplican
valor por valor, y eso no alcanza. En CIC-IDS2017, `Total Fwd Packets` aportaba
los valores 13, 16, 17, 18, 20, 23, 24, 25 y 26 — cada uno rarísimo por
separado, porque la masa está repartida entre cientos de valores, pero juntos
son la distribución normal de una variable de conteo. Con 884 candidatos así, el
detector marcaba **22.228 de 30.000 filas limpias**. Con el límite, 259.

Una puerta trasera es un valor fijo y aislado. Si una columna aporta muchos, lo
que se está viendo es su distribución.

---

## Por qué se combinan

Ningún detector alcanza solo. Lo informativo es la **coincidencia entre métodos
independientes**: una fila que `poison.knn` y `poison.trigger` señalan por
motivos distintos es mucho más sospechosa que una que solo uno puntuó alto.

```python
from vigia.core.engine import run_audit
from vigia.poison import rank_suspects

report = run_audit(ctx, module="poison")
for s in rank_suspects(report.findings, top=50, min_detectors=2):
    print(s.row, f"{s.score:.3f}", s.detectors)
```

`min_detectors=2` es el valor por defecto de la CLI, y **sirve para buscar
envenenamiento deliberado, no para buscar etiquetas mal puestas.** La diferencia
está medida y es grande:

| Qué se busca | Qué usar | Por qué |
|---|---|---|
| Envenenamiento inyectado | `min_detectors=2` | La fila es anómala de varias formas a la vez, así que varios detectores la ven |
| Ruido de etiqueta real | `min_detectors=1` | Cada fila es rara de **una** sola forma |

Sobre el ruido documentado por Engelen, los cuatro detectores casi no se
solapan: `poison.cluster` no comparte **ni una sola fila** con los otros tres.
Exigir coincidencia ahí descarta casi todos los aciertos y el rendimiento cae
de 19x sobre el azar a 2,5x.

> **La premisa "la coincidencia es la señal" resultó ser condicional.** Se
> cumple sobre envenenamiento inyectado, que es contra lo que se diseñó el
> módulo, y no se cumple sobre ruido de etiqueta natural. Lo descubrimos al
> medir contra datos reales; el simulador no podía mostrarlo, porque ahí las
> filas envenenadas son anómalas de todas las formas a la vez.

Para buscar etiquetas mal puestas conviene mirar la unión con `--min-detectors 1`
y revisar la lista de cada detector por separado.

El puntaje combinado es el **máximo** ponderado, no el promedio, más una
bonificación por cada detector que coincide. Con promedio, un detector que
acierta con confianza alta queda diluido por otros que ni miraron esa fila: en
pruebas el combinado daba F1 0,44 donde el mejor detector solo daba 0,985.

---

## El simulador

No existe un dataset público de NIDS con envenenamiento deliberado y la lista de
qué filas se tocaron. Sin esa lista, "encontró 500 filas sospechosas" no dice si
acertó o inventó, y un detector roto se ve igual que uno que funciona.

**Pero eso no obliga a usar datos sintéticos.** El simulador se aplica sobre
CIC-IDS2017 real: el tráfico es auténtico y solo el envenenamiento se inyecta.
Es bastante más exigente, y es lo que mide
`benchmarks/cic_envenenamiento_real.py`. Medir sobre flujos generados sobrestima
el rendimiento por un margen amplio.

```python
from vigia.poison import inject_label_flip

spec = inject_label_flip(df, "Label", ratio=0.02, seed=42)
print(spec.n_poisoned)  # cuántas se tocaron
print(spec.poisoned_idx)  # exactamente cuáles

# ...correr los detectores sobre spec.df...

print(spec.evaluate(detectadas))
# {'precision': 1.0, 'recall': 0.97, 'f1': 0.985, ...}
```

Tres inyecciones disponibles:

| Función | Qué hace |
|---|---|
| `inject_label_flip` | Cambia la etiqueta de un porcentaje de filas |
| `inject_backdoor` | Pone un valor fijo en una columna y la etiqueta objetivo |
| `inject_synthetic` | Agrega filas nuevas copiadas con ruido, con otra etiqueta |

También sirve por sí mismo para probar qué tan frágil es un modelo frente a
este tipo de ataque.

---

## Qué tan bien funciona

Hay dos mediciones, y la diferencia entre ellas es la parte importante.

### Sobre datos sintéticos

3.000 flujos generados, dos clases bien separadas, 2 % envenenado:

| Ataque | Mejor detector | Precisión | Recall |
|---|---|---|---|
| Cambio de etiqueta | `poison.knn` | 1,000 | 1,000 |
| Puerta trasera | `poison.trigger` | 1,000 | 1,000 |
| Inyección sintética | combinado | 1,000 | 0,970 |

Salen de `tests/unit/test_poison.py`, que falla si empeoran. **Pero estos
números no predicen el rendimiento real**: en un dataset sintético las clases
están bien separadas y cualquier fila envenenada sobresale.

### Sobre CIC-IDS2017 real

Mismo ataque, mismo porcentaje, 30.000 flujos auténticos
(`benchmarks/cic_envenenamiento_real.py`):

| Ataque | Mejor detector | Precisión | Recall | F1 |
|---|---|---|---|---|
| Puerta trasera | `poison.trigger` | 0,437 | **1,000** | **0,608** |
| Inyección sintética | `poison.loss` | 0,951 | 0,485 | **0,642** |
| Cambio de etiqueta | `poison.knn` | 0,621 | 0,478 | **0,540** |

De F1 1,000 a 0,608 en el mejor caso. El tráfico real tiene colas largas,
columnas correlacionadas y filas genuinamente raras que no son envenenamiento.

**Control de falsos positivos sobre datos reales:** 104 filas de 30.000 (0,3 %)
son señaladas por dos detectores en un dataset sin envenenar.

### La puerta trasera pasó de indetectable a recall 1,000

Daba F1 0,007 hasta que se midió por qué. Eran dos filtros:

`Destination Port` tiene 4.931 valores distintos en 30.000 filas, y el detector
**descartaba la columna entera** por tener más de `n/10` valores únicos. El
criterio correcto no es cuántos valores distintos hay sino si el valor se
repite, que es lo que un trigger necesita para que el modelo lo aprenda.

El segundo era el límite de frecuencia global. Una puerta trasera en
exactamente el 2 % de las filas da 2,0033 % cuando alguna fila ya tenía ese
valor, cruzaba el límite del 2 % y se volvía invisible — mientras que al 1,5 %
se detectaba con recall 1,000. Fallar por tres milésimas es demasiado frágil,
así que el límite lleva un 10 % de holgura.

> Subir el umbral al 3 % parecía más simple y reintrodujo los falsos positivos
> que ese límite existe para evitar. La holgura acotada fue la única forma de
> arreglar el borde sin romper lo demás.

### Ruido de etiqueta real

La única verdad de referencia que no inyectamos nosotros. Engelen et al.
marcaron con `Attempted-relabel-as-Benign` los flujos que el dataset original
daba por ataque sin serlo (`benchmarks/cic_ruido_engelen.py`):

| Detector | Precisión | Contra el azar |
|---|---|---|
| `poison.trigger` | 0,088 | **19,2x** |
| `poison.cluster` | 0,035 | 7,6x |
| `poison.loss` | 0,030 | 6,5x |
| `poison.knn` | 0,010 | 2,2x |
| combinado (`min_detectors=2`) | 0,011 | 2,5x |

Entre los cuatro encuentran **el 57 % de las filas mal etiquetadas**. Los
detectores sirven; la precisión individual es baja porque el ruido real es
sutil.

---

## Limitaciones

**Los detectores caros trabajan sobre una muestra.** `poison.knn` y
`poison.cluster` son cuadráticos o peor: por encima de 50.000 filas se muestrea.
Los índices que devuelven son del dataset completo, pero la cobertura es
parcial.

**Un puntaje alto no es un veredicto.** Es motivo para mirar la fila, no para
borrarla. Un dataset real tiene filas raras que no son envenenamiento.

**Un envenenamiento por encima del 2 % de las filas es invisible para
`poison.trigger`.** El límite de frecuencia global define el techo de lo que el
detector puede ver: un valor más frecuente que eso se considera una
característica del tráfico, no un trigger. Es la contrapartida de no marcar el
74 % de un dataset limpio, y por eso el detector supone que lo envenenado es
minoría.

**No cubre clean-label.** Un ataque que usa etiquetas correctas pero elige
ejemplos que mueven la frontera de decisión no deja ninguna de las huellas que
estos cuatro detectores buscan. El diseño lo marca como v2.

**El envenenamiento masivo se vuelve invisible.** Si el 30 % del dataset está
envenenado, deja de ser una anomalía y pasa a ser el patrón. Estos métodos
suponen que lo envenenado es minoría.
