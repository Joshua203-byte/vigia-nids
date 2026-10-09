# Catálogo de checks

Referencia de los 17 hallazgos que puede emitir el auditor: 16 checks, más
`dup.class_ratio`, que lo emite `dup.exact`. Es la misma lista que muestra
`vigia checks`. Para cada uno: qué busca, cómo lo mide, cuándo lo considera
grave y qué hacer al respecto.

Si llegaste acá con un hallazgo en la mano, buscá su id.

**Índice:** [Duplicados](#duplicados) · [Fugas](#fugas) · [Atajos](#atajos) ·
[Etiquetas](#etiquetas) · [Validez](#validez) · [Cuándo se salta un check](#cuándo-se-salta-un-check)

---

## Duplicados

**Qué cuenta como "la misma fila".** Las características, sin la etiqueta ni el
split, y sin las columnas de tiempo e IP que el usuario declaró con `--time-col`,
`--src-ip-col`, `--dst-ip-col` o con un perfil: el mismo flujo visto desde otro
host o en otra hora es un duplicado. Esas columnas siguen siendo características
para los checks de atajos y de fuga. Lo mismo vale para `labels.conflict`.

### `dup.exact`

**Qué busca.** Filas idénticas: mismas características y misma etiqueta.

**Cómo.** Hash de la fila (`hash_rows()` nativo de Polars) sobre las
características más la etiqueta. Los valores del hash solo se comparan dentro de
una misma ejecución.

**Severidad.** `high` desde el 20 % de filas duplicadas, `medium` desde el 5 %,
`low` por debajo.

**Por qué importa.** Los duplicados inflan las métricas porque el modelo se
evalúa con ejemplos que ya vio. Un porcentaje alto no siempre es un error: los
ataques repetitivos como DoS generan flujos casi idénticos por diseño. Lo grave
es que crucen entre conjuntos (ver `dup.cross_split`).

**Corrección.** `drop_duplicates`

**Referencia.** CIC-IDS2017 tiene 308.381 duplicados (10,89 %).

### `dup.class_ratio`

Lo emite `dup.exact`: pedir `--checks dup.class_ratio` corre ese check.

**Qué busca.** Clases donde más de la mitad de las filas son copias.

**Cómo.** Duplicados por clase, filtrando las que tienen al menos 10 filas.

**Severidad.** `medium`.

**Por qué importa.** El número efectivo de ejemplos distintos es mucho menor que
el conteo de filas, así que el recall reportado para esa clase no es confiable.

**Corrección.** `drop_duplicates`

**Nota.** Lo emite `dup.exact`, pero se puede pedir por su propio id.

### `dup.cross_split`

**Qué busca.** La misma fila en entrenamiento y en prueba.

**Cómo.** Hashes presentes en más de un valor de la columna de split. Las filas
sin split asignado se excluyen y se reportan en `n_unassigned`.

**Severidad.** Siempre `critical`.

**Por qué importa.** El modelo es evaluado con ejemplos idénticos a los que usó
para entrenar. Las métricas no miden generalización sino memorización.

**Corrección.** `drop_duplicates`, y dividir con `group_split`.

**Referencia.** Con split aleatorio, CIC-IDS2017 deja 288.790 filas a ambos
lados. NSL-KDD —cuyo propósito declarado es no tener duplicados— tiene 610.

### `dup.near`

**Qué busca.** Filas casi idénticas que `dup.exact` no puede ver porque no son
copias byte a byte: dos flujos que difieren en unas pocas columnas, típicamente
por ruido de precisión numérica o un contador con una pequeña variación entre
capturas del mismo evento. Con el umbral por defecto (0,9), que difieran en una
sola columna solo alcanza si hay al menos 19 (Jaccard = (n−1)/(n+1)); con
menos columnas, dos filas deben coincidir en proporcionalmente más.

**Cómo.** MinHash LSH (`datasketch`) sobre un conjunto de tokens
`"columna=valor"` por fila (numéricos redondeados a 4 decimales, para que el
ruido de punto flotante no infle el Jaccard falso). Las **repeticiones** de un
duplicado exacto se excluyen antes de buscar pares, para no solaparse con
`dup.exact`; la primera aparición de cada fila queda como representante, así el
casi-duplicado de una fila repetida (el caso del DoS repetitivo) se sigue
viendo. Los pares conectados se agrupan en clusters.

**Severidad.** `high` desde el 10 % de filas afectadas, `medium` desde el 2 %,
`low` por debajo.

**Por qué importa.** Un modelo no distingue "casi el mismo ejemplo" de "el
mismo ejemplo": si estas filas cruzan entre entrenamiento y prueba, el efecto
es el mismo que `dup.cross_split` aunque el hash no coincida.

**Corrección.** Ninguna automática: a diferencia de un duplicado exacto,
decidir si dos filas "casi iguales" son el mismo evento o dos eventos
legítimos parecidos requiere criterio humano.

**Configuración.** `near_duplicate_threshold` (por defecto `0.9`): similitud
de Jaccard mínima para considerar dos filas casi duplicadas. Valores por
encima de `0.98` no son soportados por el número de permutaciones de
`datasketch` que usa Vigía y el check se salta con un mensaje explicando por
qué.

**Límite.** Por costo, sobre 200.000 filas revisa una muestra al azar y lo
dice en la descripción. El resultado es una cota inferior: dos copias solo se
ven si las dos caen en la muestra. Medido en el testing-set de UNSW-NB15
(82.332 filas), con el 49 % de las filas ve el 90 % de los casi-duplicados, con
el 24 % el 81 % y con el 10 % el 62 %. `--streaming` excluye este check.

**Requiere.** `pip install 'vigia-nids[ml]'` (trae `datasketch`); sin eso, se
salta con el mensaje de instalación.

---

## Fugas

### `leak.temporal`

**Qué busca.** Que el conjunto de prueba no sea posterior al de entrenamiento.

**Cómo.** Compara los rangos de tiempo de cada split. Una fila de prueba
simultánea al último instante de entrenamiento cuenta como solape: en
CIC-IDS2017 el timestamp tiene granularidad de segundo y miles de flujos
comparten instante.

**Cómo interpreta la fecha.** Prueba varios formatos y se queda con el que
interpreta más valores. No descarta en silencio lo que no entiende: si queda sin
interpretar más del 0,1 % de los valores (o de las filas de entrenamiento y
prueba sin tiempo), se salta diciendo cuántos, porque esas filas pueden ser
justo las que filtran. Si día/mes y mes/día interpretan todo y ordenan las filas
distinto (`07/08/2017`), la columna es ambigua: se salta y pide el formato con
`--time-format` (`vigia.load(time_format=...)`, `time_format` en un perfil o en
la petición de la API). `temporal_split` usa el mismo parser, y deja sin split
las filas sin tiempo en vez de mandarlas a prueba.

**Severidad.** `critical` si la prueba es anterior al entrenamiento, si está
contenida dentro de su periodo, o si el solape supera el 50 %. `high` si es
parcial.

**Por qué importa.** Un NIDS en producción detecta ataques que todavía no
ocurrieron. Evaluar sin respetar el orden temporal mide otra cosa
(Pendlebury et al., TESSERACT).

**Corrección.** `temporal_split`

### `leak.host`

**Qué busca.** El mismo host en entrenamiento y en prueba.

**Cómo.** Agrupa por IP de origen y de destino, y busca las que aparecen a
ambos lados.

**Severidad.** `critical` si afecta al 50 % o más de las filas de prueba,
`high` si no.

**Por qué importa.** En un dataset de laboratorio el atacante usa siempre las
mismas máquinas. Si esas IPs están en ambos splits, el modelo memoriza el host
y la métrica no dice nada sobre un atacante nuevo.

**Corrección.** `group_split` con `group_by="host"`.

**Nota.** El split temporal **no** elimina esta fuga: los equipos del
laboratorio son los mismos todos los días.

### `leak.session`

**Qué busca.** Flujos de la misma conexión repartidos entre splits.

**Cómo.** Agrupa por la 5-tupla (IP origen, IP destino, puerto origen, puerto
destino, protocolo). Si falta **alguna** de las cinco columnas, el check se
salta en vez de degradarse a un par host-servicio, que es lo que ya mira
`leak.host`. (Antes de la 1.0.0 corría con cuatro.) No considera ventana de
tiempo: una 5-tupla reutilizada semanas después cuenta como la misma sesión.

**Severidad.** `critical` desde el 10 % de las filas de prueba, `high` si no.

**Por qué importa.** CICFlowMeter parte una conexión larga en varios flujos por
timeout. Si esos trozos caen a ambos lados, el modelo evalúa la continuación de
algo que ya estudió. Es más fina que `leak.host` y sobrevive a dividir por IP.

**Corrección.** `group_split`

**Referencia.** 31.137 conexiones repartidas en el viernes de DDoS de
CIC-IDS2017 con split aleatorio.

---

## Atajos

### `shortcut.single_feature`

**Qué busca.** Una sola columna que predice la etiqueta demasiado bien.

**Cómo.** Exactitud balanceada de la regla "predecir la clase mayoritaria de
cada valor", calculada con un `group_by` en vez de entrenar un modelo por
columna: la señal es la misma y corre sobre millones de filas.

**Umbral.** 0,95 por defecto (`--shortcut-threshold`).

**Severidad.** `critical`.

**Por qué importa.** El modelo luce perfecto en el laboratorio y falla en una
red real, porque aprendió la IP del atacante y no el ataque.

**Corrección.** `drop_identifiers` si el nombre delata un identificador.

**Falso positivo que evita.** Una columna con un valor distinto por fila da
exactitud 1,0 trivialmente: acertar es memorizar. Por eso las columnas con más
del 30 % de valores únicos o menos de 3 filas por valor no se miden por valor.

- Si son **numéricas** (una tasa, una duración, un tamaño), se discretizan por
  cuantiles (hasta 50 tramos, al menos 20 filas por tramo) y se aplica la misma
  regla a los tramos: es lo que aprende un árbol con un par de cortes. Antes se
  descartaban, y un umbral perfecto sobre una columna continua no lo reportaba
  nadie. Sobre ruido continuo la exactitud por tramos queda cerca del azar.
  Límite: una clase más rara que un tramo no se ve.
- Si son **de texto** (IPs, ids), no hay orden que discretizar: las cubre
  `shortcut.identifier` por el nombre.

**Referencia.** En CIC-IDS2017, `Source IP` sola alcanza **0,9992**.

### `shortcut.identifier`

**Qué busca.** Columnas identificadoras usadas como características: IPs, IDs
de flujo, timestamps, direcciones MAC.

**Cómo.** Patrones sobre el nombre normalizado de la columna. No marca las
columnas de rol (tiempo, IPs de origen y destino) que el usuario declaró con
`--time-col`, `--src-ip-col`, `--dst-ip-col` o con un perfil: ya dijo que son
metadatos. Las que solo se detectaron por nombre se siguen marcando. Una IP
declarada que delata la etiqueta la encuentran `shortcut.single_feature` y los
checks de fuga.

**Severidad.** `high`.

**Por qué importa.** Identifican al host, al flujo o al momento de la captura
en vez de describir el comportamiento del tráfico.

**Corrección.** `drop_identifiers`

---

## Etiquetas

### `labels.conflict`

**Qué busca.** Filas con características idénticas y etiquetas distintas.

**Cómo.** Agrupa por el hash de las características (sin la etiqueta) y busca
grupos con más de una etiqueta.

**Severidad.** `critical` desde el 1 % de las filas, `high` si no.

**Por qué importa.** No pueden ser ambas correctas: o la etiqueta está mal, o a
las características les falta lo que distingue los dos casos. En cualquiera de
los dos escenarios hay un techo de exactitud que ningún modelo puede superar.

**Filas sin etiqueta.** No cuentan: sin etiqueta no hay dos que se contradigan.
(Antes de la 1.0.0 una fila sin etiqueta con las mismas características que una
etiquetada hacía fallar el check.)

**Referencia.** 48 grupos (1.091 filas) en el miércoles de CIC-IDS2017, casi
todos entre `BENIGN` y `DoS Hulk`.

### `labels.noise`

**Qué busca.** Etiquetas que contradicen al resto del dataset.

**Cómo.** *Confident learning* (cleanlab) sobre probabilidades fuera de muestra
de una regresión logística con validación cruzada de 3 pliegues. Sobre más de
200.000 filas trabaja con una muestra.

**Severidad.** `high` desde el 1 % de las filas evaluadas, `medium` si no. No
reporta nada por debajo del 0,1 % (`noise_min_ratio`): medido con ruido
inyectado, ese umbral conserva todo ruido real de 0,35 % o más y calla las
alarmas fantasma de datasets separables.

**Por qué importa.** Son candidatas a revisión humana, no un veredicto.

**Corrección.** `quarantine_noise` — nunca borra, aparta.

**Dos guards que lo hacen confiable:**

1. **Excluye las columnas identificadoras antes de entrenar.** Si el modelo
   auxiliar puede mirar la IP del atacante, acierta memorizando y no detecta
   ruido alguno. Es la advertencia explícita de la sección 8.3 del diseño.
2. **Exige que el modelo supere a la clase mayoritaria**: tiene que eliminar al
   menos el 25 % del error de la regla "predecir siempre la mayoritaria"
   (`(exactitud − base) / (1 − base) ≥ 0,25`). Sin esto, cuando las columnas no
   predicen la etiqueta, cleanlab marca como ruido casi toda la clase
   minoritaria: sobre el dataset de control reportaba un 37,5 % inexistente. El
   margen es relativo para que funcione con clases muy desbalanceadas: con uno
   absoluto de 5 puntos, una mayoritaria de 95 % o más dejaba el check sin
   poder correr nunca.

El hallazgo incluye `exactitud_modelo_auxiliar` y
`exactitud_clase_mayoritaria` para que se pueda juzgar cuánto confiar en él.

**Solapamiento de clases.** El método no distingue una etiqueta mala de un
ejemplo en la zona donde dos clases se solapan, y la exactitud del modelo no
los separa. Lo que sí acota es cuánto pudo sobreestimar: medido con ruido
inyectado, el máximo observado fue 0,6 puntos con exactitud de 0,97 o más, 3,1 entre
0,90 y 0,97, 8,3 entre 0,80 y 0,90 y 14,8 por debajo. El hallazgo trae esa cota
(`sobreestimacion_maxima_observada`) como indicación, no como garantía.

### `labels.taxonomy`

**Qué busca.** La misma clase escrita de varias formas: `DoS Hulk`, `DoS-Hulk`,
`dos hulk`.

**Cómo.** Normaliza a minúsculas sin signos y agrupa las que colisionan.

**Severidad.** `high`.

**Por qué importa.** Para el modelo son clases distintas: reparte los ejemplos
entre ellas y reporta una métrica por cada variante, y ninguna refleja el
rendimiento real sobre ese ataque.

**Corrección.** `normalize_labels`

### `labels.imbalance`

**Qué busca.** Clases con tan pocos ejemplos que su métrica no permite comparar
modelos.

**Cómo.** Umbral de 100 ejemplos, acotado al 10 % del dataset para que en
archivos chicos no describa a casi todas las clases.

**Severidad.** `medium`.

**Por qué importa.** Un recall de 0,50 sobre 11 ejemplos no distingue un modelo
bueno de uno malo: cada ejemplo vale 9 puntos porcentuales.

**Referencia.** Heartbleed tiene 11 filas en CIC-IDS2017, SQL Injection 21,
Infiltration 36.

---

## Validez

### `validity.nan_inf`

**Qué busca.** Nulos, NaN e infinitos en columnas numéricas.

**Cómo.** Por columna. Las que comparten exactamente el mismo recuento se
agrupan en un solo hallazgo: un recuento idéntico en decenas de columnas apunta
a una causa común (filas truncadas o sin etiqueta), no a un problema
independiente de cada una.

**Severidad.** `high` si hay algún infinito o supera el 5 % de las filas,
`medium` desde el 1 %, `low` si no.

**Por qué importa.** Los infinitos rompen el entrenamiento. En CIC-IDS2017
vienen de dividir entre una duración de cero al calcular tasas.

**Referencia.** Los CSV de CIC-IDS2017 traen `Infinity` en `Flow Bytes/s` y
`Flow Packets/s`: 2.867 infinitos en `Flow Packets/s`, y 1.509 infinitos más
1.358 NaN en `Flow Bytes/s` (ver `benchmarks/RESULTADOS.md`). En la versión con
IPs (`GeneratedLabelledFlows`) hay además 78 columnas con 288.602 nulos cada
una: las filas vacías del día de ataques web.

**Cómo se leen.** `Infinity`, `-Infinity` y `NaN` del CSV se conservan como
infinitos y NaN reales, no como nulos. Antes de la 1.0.0 se leían como nulos y los
infinitos de CICFlowMeter salían como un hallazgo `low` sin infinitos.

### `validity.impossible`

**Qué busca.** Valores que el dominio de red no permite: puertos fuera de
0–65535, duraciones o bytes negativos.

**Cómo.** Reglas por patrón en el nombre de la columna.

**Severidad.** `high`.

**Por qué importa.** Suele indicar un error del extractor de flujos o un
desalineamiento de columnas.

**Falso positivo que evita.** `-1` en las ventanas TCP iniciales
(`Init_Win_bytes_*`) es el centinela de "no aplica" de CICFlowMeter, no un
error. Sin esta excepción se reportaban 523.589 filas falsas que enterraban los
40 desbordamientos reales.

**Referencia.** Desbordamientos de entero en `Fwd/Bwd Header Length`, con
valores como **-1.929.349.973**.

### `validity.constant`

**Qué busca.** Columnas con un solo valor distinto, sin contar los nulos: una
columna `[7, 7, 7, null]` es constante, y una toda nula también. Lo mismo vale
para `drop_constant` y para el modo `--streaming`.

**Severidad.** `low`.

**Por qué importa.** No aportan información pero ocupan memoria y ensucian la
importancia de características.

**Corrección.** `drop_constant`

### `validity.column_names`

**Qué busca.** Nombres con espacios al inicio o al final, y nombres que quedan
duplicados al normalizarlos.

**Severidad.** `low` para los espacios, `medium` para los duplicados.

**Por qué importa.** Los espacios provocan errores silenciosos al seleccionar
columnas por nombre. Es típico de los CSV de CICFlowMeter: `" Destination Port"`.

**Corrección.** `strip_column_names`

---

## Cuándo se salta un check

Un check saltado **no es un error del programa**: es que le falta la columna que
necesita para trabajar. Aparece en la sección "checks no ejecutados" del reporte
con el motivo. Un check que **falló** por un bug es otra cosa: va aparte, en
"checks que fallaron" (`errors` en el JSON), pone el semáforo en rojo y hace que
la CLI salga con código 3.

| Motivo | Qué hacer |
|---|---|
| `requiere 'split_col'` | Pasar `--split-col`, o crear la partición |
| `requiere 'time_col'` | Pasar `--time-col` |
| `no se identificó ninguna columna de IP` | Pasar `--src-ip-col` / `--dst-ip-col` |
| `requiere la 5-tupla` | Faltan IPs, puertos o protocolo (las cinco columnas); `leak.host` sigue cubriendo el caso |
| `el formato de la columna de tiempo es ambiguo` | Día/mes o mes/día: pasar `--time-format` |
| `N de M valores de tiempo no se pudieron interpretar` | Normalizar la columna o pasar `--time-format` |
| `la columna de etiqueta tiene una sola clase` | El dataset no permite este análisis |
| `el modelo auxiliar no supera a la clase mayoritaria` | Las columnas no predicen la etiqueta (no eliminan al menos el 25 % del error de la regla trivial); no se puede distinguir ruido de falta de señal |
| `requiere scikit-learn y cleanlab` | `pip install 'vigia-nids[ml]'` |

Preferimos saltarnos un check antes que correrlo sobre la columna equivocada.
Un número inventado se parece demasiado a un resultado.

**Por eso existe el semáforo gris:** sin hallazgos pero con checks saltados no
es verde. Los que más se saltan son los que dependen de la etiqueta o del split,
o sea los que detectan fuga y duplicados cruzados. Dar verde ahí le diría a
quien tiene la columna mal nombrada que su dataset está limpio.
