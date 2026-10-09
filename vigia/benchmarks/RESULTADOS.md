# Resultados sobre datasets públicos

Cada hallazgo de esta página fue verificado a mano con Polars puro, sin usar
Vigía, antes de darlo por bueno. La idea no es que la herramienta encuentre
cosas, sino que lo que encuentra sea cierto.

Los datos no se redistribuyen: cada dataset se descarga de su fuente. Quien use
CIC-IDS2017 debe citar a sus autores: Sharafaldin, I., Habibi Lashkari, A. y
Ghorbani, A. A., *Toward Generating a New Intrusion Detection Dataset and
Intrusion Traffic Characterization*, ICISSP 2018. La versión corregida es de
Engelen, G., Rimmer, V. y Joosen, W., *Troubleshooting an Intrusion Detection
Dataset: the CICIDS2017 Case Study*, IEEE Security and Privacy Workshops (SPW),
2021, doi:10.1109/SPW53761.2021.00009.

## NSL-KDD

- **Fuente:** https://github.com/jmnwong/NSL-KDD-Dataset (`KDDTrain+.txt` + `KDDTest+.txt`)
- **Tamaño:** 148.517 filas × 44 columnas (train 125.973 + test 22.544)
- **Preparación:** los dos archivos concatenados con una columna `split`, que es
  lo que haría cualquiera al entrenar con el split oficial.
- **Tiempo de auditoría:** 1,7 s
- **Semáforo:** ROJO

| Check | Hallazgo | Verificado |
|---|---|---|
| `dup.cross_split` | 1.220 filas aparecen en train y en test | Sí |
| `dup.exact` | 610 filas duplicadas (0,41 %) | Sí |
| `validity.constant` | `num_outbound_cmds` constante en 0 | Sí |

Saltados correctamente: `leak.temporal` y `leak.host` (el dataset no tiene
columna de tiempo ni de IP; son características agregadas de conexión).

### El hallazgo que importa

NSL-KDD existe **porque** KDD'99 tenía duplicados masivos: sus autores los
quitaron a propósito, y por eso el dataset se usa desde 2009. La auditoría
confirma que hicieron ese trabajo, pero a medias:

| Conjunto | Filas | Filas únicas | Duplicados internos |
|---|---|---|---|
| train | 125.973 | 125.973 | **0** |
| test | 22.544 | 22.544 | **0** |
| **cruce train↔test** | | | **610 filas compartidas** |

Cada conjunto está perfectamente deduplicado por dentro, pero deduplicar cada
archivo por separado no ve el cruce entre ellos. Son 610 filas idénticas —mismas 41 características y misma
etiqueta— que están a la vez en entrenamiento y en prueba: el 2,7 % del
conjunto de prueba son ejemplos que el modelo ya vio.

Ejemplo concreto (un `neptune`, o sea un SYN flood):

```
duration=0  protocol_type=tcp  service=private  flag=REJ
src_bytes=0  dst_bytes=0  land=0  wrong_fragment=0  …  class=neptune
```

No invalida el dataset —un 2,7 % no explica un F1 de 0,99— pero es justo el
tipo de error que nadie mira porque el trabajo de deduplicación "ya se hizo".
Es la clase de hallazgo para la que existe `dup.cross_split`.

### Qué se puso a prueba de Vigía

- Detección automática de columnas sobre nombres que no inventamos: encontró
  `class` y `split` sin ayuda.
- 148 mil filas sin problemas de memoria ni de tiempo.
- Los checks que no aplican se saltan y lo dicen, en vez de correr sobre la
  columna equivocada o de callarse.

## CIC-IDS2017 (original)

- **Fuente:** https://www.unb.ca/cic/datasets/ids-2017.html → `MachineLearningCSV.zip`
- **Tamaño:** 2.830.743 filas × 80 columnas, 844 MB en 8 CSVs (uno por turno de captura)
- **Tiempo de auditoría:** 95 s sobre la carpeta completa; 4,2 s sobre el lunes solo
- **Semáforo:** ROJO

| Check | Hallazgo | Verificado |
|---|---|---|
| `dup.exact` | 308.381 filas duplicadas (10,89 %) | Sí |
| `validity.impossible` | 115 duraciones negativas, 85 tasas negativas | Sí |
| `validity.impossible` | 35 + 22 desbordamientos en `Fwd/Bwd Header Length` | Sí |
| `validity.nan_inf` | `Flow Packets/s`: 2.867 infinitos. `Flow Bytes/s`: 1.509 infinitos y 1.358 NaN | Sí (re-medido el 06/10/2026, ver abajo) |
| `validity.constant` | 8 columnas constantes | Sí |

Los duplicados y los infinitos son los defectos más citados del dataset. Los
desbordamientos de `Header Length` son valores como **-1.929.349.973**: un bug
conocido de CICFlowMeter, no ruido estadístico.

> **Corrección posterior (auditoría de la 1.0, SCI-07; re-medido el
> 06/10/2026).** Esta tabla decía "2.867 infinitos en `Flow Bytes/s` y `Flow
> Packets/s`". El lector de entonces tenía `Infinity`, `-Infinity` y `NaN` en
> `null_values` y los convertía a todos en nulos: 2.867 era la cantidad de
> **valores no finitos** de cada columna, no de infinitos. Con el lector
> actual, que los conserva, y sobre los mismos 8 CSV (Vigía 1.0.0, Polars puro
> para contar): `Flow Packets/s` tiene 2.867 infinitos; `Flow Bytes/s`, 1.509
> infinitos y 1.358 NaN. `validity.nan_inf` los reporta como `high`; antes
> salían como nulos de severidad baja.

El lector detectó por sí solo la columna `Fwd Header Length` **repetida** en la
cabecera (Polars la renombra `_duplicated_0`), que es otro defecto documentado
del dataset.

### El experimento: split aleatorio contra split temporal

CIC-IDS2017 no trae columna de split, así que cada quien la inventa. Casi toda
la literatura parte el dataset al azar. `benchmarks/cic_split_experiment.py`
arma las dos variantes desde los mismos datos y audita cada una:

| | Split aleatorio (70/30) | Split temporal (lun–mié / jue–vie) |
|---|---|---|
| `dup.cross_split` | **CRÍTICO — 262.241 filas** | *(ningún hallazgo)* |
| `dup.exact` | 9,40 % | 9,40 % |
| `validity.*` | idéntico | idéntico |
| **Semáforo** | ROJO con crítico | ROJO sin críticos |

Mismos datos, misma herramienta, misma semilla: lo único que cambia es cómo se
parte. El split aleatorio deja **262.241 filas idénticas a ambos lados**, o sea
que el 9 % del conjunto de prueba son ejemplos que el modelo ya vio. Al cortar
por día de captura, ese hallazgo desaparece por completo.

Es la demostración de para qué sirve la herramienta: el error no está en los
datos, está en cómo se los usa, y es invisible hasta que alguien lo mide.

### Falso positivo encontrado y corregido

La primera corrida reportó 224.495 valores fuera de rango en
`Init_Win_bytes_forward` y 299.094 en `Init_Win_bytes_backward` — el 42 % y el
56 % de las filas del lunes. Verificado a mano: el único valor negativo es
`-1`, que CICFlowMeter usa para "no aplica" cuando el flujo nunca estableció
una ventana TCP.

No era solo ruido: esas 523.589 filas falsas enterraban los 40 desbordamientos
reales, que son lo que había que ver. Corregido en `SENTINEL_PATTERNS`.

### Limitación de esta variante

`MachineLearningCSV.zip` trae solo las 78 características numéricas: **no tiene
`Timestamp` ni `Source IP`**, así que `leak.temporal` y `leak.host` no pueden
correr y lo declaran. Para ejercitarlos hace falta `GeneratedLabelledFlows.zip`,
que sí conserva esas columnas (abajo).

## CIC-IDS2017 (GeneratedLabelledFlows)

La otra variante del mismo dataset: conserva `Flow ID`, `Source IP`,
`Destination IP`, `Source Port` y `Timestamp`. 2.830.743 filas × 85 columnas,
1,2 GB. Es la que permite ejercitar los checks de fuga.

### El experimento completo, con los cuatro checks activos

Re-medido el 06/10/2026 sobre la 1.0.0 (`main`, `96c50e5`):

| | Split aleatorio (70/30) | Split temporal (lun–mié / jue–vie) |
|---|---|---|
| `dup.cross_split` | **CRÍTICO — 288.790 filas** | *(ningún hallazgo)* |
| `leak.session` | **CRÍTICO — 249.723 sesiones** | CRÍTICO — 118.258 sesiones |
| `leak.host` (Source IP) | CRÍTICO — 11.515 hosts | CRÍTICO — 7.465 hosts |
| `leak.host` (Destination IP) | CRÍTICO — 15.323 hosts | CRÍTICO — 8.889 hosts |
| `leak.temporal` | *(saltado)* | *(saltado)* |
| `dup.exact` | 9,26 % | 9,26 % |
| **Críticos** | **4** | **3** |

**Dos cambios respecto de la primera versión de esta tabla.** `leak.temporal`
daba "CRÍTICO — 100 % de solape" en el split aleatorio y nada en el temporal;
ahora se salta en los dos con el motivo: 288.602 filas (las filas vacías del día
de ataques web) no tienen tiempo, y no se puede afirmar que el split respete el
orden temporal sin saber dónde caen. Antes las descartaba en silencio
(auditoría de la 1.0, SCI-01). Y `leak.session`, que no figuraba en la tabla,
reporta las sesiones (5-tupla) que aparecen a ambos lados.

Cortar por día elimina por completo los duplicados entre conjuntos y reduce a
la mitad las sesiones compartidas. La fuga por host **no desaparece**, solo baja: los mismos equipos del
laboratorio siguen apareciendo a ambos lados, porque la red es la misma todos
los días. Para eliminarla haría falta dividir por host, no por tiempo. Es
información útil: dice que el corte temporal, por sí solo, no alcanza.

### El atajo que justifica el proyecto

Sobre el viernes de DDoS, `shortcut.single_feature` encontró:

| Columna | Exactitud balanceada |
|---|---|
| **`Source IP`** | **0,9992** |
| `Destination IP` | 0,9958 |
| `Total Length of Fwd Packets` | 0,9884 |
| `Average Packet Size` | 0,9586 |
| `Destination Port` | 0,9543 |

Re-medido el 06/10/2026 sobre la 1.0.0: las cinco cifras son idénticas. La 1.0.0
marca además `Subflow Fwd Bytes` (0,9884, la misma columna que `Total Length of
Fwd Packets` con otro nombre), `Fwd Header Length` (0,9523) y su copia
`Fwd Header Length_duplicated_0`: 8 columnas críticas en total.

**La IP de origen sola predice la etiqueta con 99,92 % de exactitud balanceada.**
Un modelo entrenado con esta columna no aprende a detectar un DDoS: aprende qué
máquina del laboratorio hacía de atacante. Puesto en una red real, no sirve.
Es exactamente el fallo que la sección 8.5 del documento de diseño describe, y
la razón por la que la versión corregida del dataset elimina esas columnas.

### Dos defectos del dataset encontrados por el camino

**El archivo que no se podía leer.** `Thursday-WorkingHours-Morning-WebAttacks`
etiqueta los ataques como `Web Attack \x96 Brute Force`, con un guion largo en
Windows-1252. Polars rechazaba el archivo entero por ese byte, así que uno de
los ocho días era imposible de auditar. Corregido en el lector.

**Las filas sin etiqueta.** Al poder leer ese archivo aparecieron **288.602
filas —el 63 %— sin ninguna etiqueta**, con todas sus columnas numéricas
vacías. Estaban ahí desde siempre, tapadas por el error de codificación.

Eso, a su vez, destapó un problema de presentación: `validity.nan_inf` emitía
80 hallazgos repitiendo la misma cifra, uno por columna, y los críticos de fuga
quedaban sepultados al final del reporte. Ahora las columnas con idéntico
recuento se agrupan y se nombra la causa común: de 87 hallazgos a 15.

## Original contra corregido: la validación

La prueba que decide si la herramienta sirve. Si los defectos que Vigía
encuentra en el original desaparecen en la versión que sus autores corrigieron,
está midiendo lo que dice medir. Si no, o los está inventando o la corrección
no los cubría — y en cualquier caso hay que saberlo.

- **Original:** `GeneratedLabelledFlows`, 2.830.743 filas × 85 columnas
- **Corregido:** Distrinet/Engelen et al. (2021), 1.787.358 filas × 84 columnas
- **Script:** `benchmarks/cic_original_vs_corregido.py`

| Check | Original (aleat.) | Original (temp.) | Corregido (aleat.) | Corregido (temp.) |
|---|---|---|---|---|
| `dup.cross_split` | 1 | 0 | **0** | **0** |
| `dup.exact` | 1 | 1 | **0** | **0** |
| `leak.host` | 2 | 2 | · | · |
| `leak.temporal` | 1 | 0 | · | · |
| `shortcut.identifier` | 1 | 1 | **0** | **0** |
| `validity.constant` | 1 | 1 | **0** | **0** |
| `validity.impossible` | 6 | 6 | **0** | **0** |
| `validity.nan_inf` | 3 | 3 | **0** | **0** |
| **Semáforo** | ROJO | ROJO | GRIS | GRIS |

`·` = el check no pudo correr. **Cero hallazgos en el corregido, en todas las
categorías que pudieron evaluarse.**

Verificado aparte con Polars puro: el corregido tiene 1.787.358 filas y
**1.787.358 únicas — cero duplicados**. Los autores los eliminaron todos, y
Vigía no reporta ninguno. Tampoco quedan infinitos, ni valores fuera de rango,
ni columnas constantes.

También desaparece `shortcut.identifier`: la versión corregida **elimina
`Source IP`, `Destination IP`, `Flow ID` y `Timestamp`**, que son exactamente
las cuatro columnas que Vigía señalaba como identificadoras, y la razón por la
que `Source IP` alcanzaba 99,92 % de exactitud balanceada en el original.

Es la validación que se buscaba: lo que la herramienta marca coincide con lo
que un equipo independiente encontró y corrigió (Engelen, Rimmer y Joosen, IEEE SPW 2021). Un trabajo posterior, de Liu, Engelen, Lynar, Essam y Joosen (IEEE CNS 2022), revisa los errores de CIC-IDS-2017 y de CSE-CIC-IDS-2018.

### Por qué el corregido da GRIS y no VERDE

Al no tener columnas de IP ni de tiempo, `leak.host`, `leak.temporal` y
`leak.session` (que exige las dos IPs) no pueden correr; la tabla de arriba
muestra los dos primeros, y el tercero se agregó después. El semáforo gris lo
dice en vez de dar un verde que se leería como "este dataset está limpio" cuando
en realidad tres de los checks más importantes nunca miraron nada.

Es el caso de uso para el que se agregó ese estado, apareciendo solo sobre datos
reales.

### Un error de método encontrado en el propio banco de pruebas

La primera corrida comparó solo 4 días: el marcador `"dos-"` del miércoles
(`DoS-Wednesday`) también coincide con `Portscan-DDos-Botnet-Friday`, así que el
viernes se asignaba al día 3 y se descartaba, llevándose consigo el DDoS, el
portscan y el botnet.

El resultado igual daba "cero hallazgos en el corregido", o sea que la
conclusión no habría cambiado — pero habría estado sostenida por una comparación
incompleta. Por eso la tabla ahora distingue `0` de `·`: sin esa distinción, un
check que no pudo correr se lee igual que uno que corrió y no encontró nada.

## Cuánto del rendimiento era real (R9)

El experimento que convierte los hallazgos en un número. Mismo modelo
(LightGBM, parámetros y semilla fijos), mismos 3.119.345 flujos, tres formas de
preparar los datos. Script: `benchmarks/cic_antes_despues.py`.

Medido de nuevo el 06/10/2026 sobre `main` (`96c50e5`, la 1.0.0). Las cifras
de A y B cambiaron respecto de las que se publicaron el 19/09; la explicación
está abajo, en "Por qué cambiaron A y B".

| | A. Aleatorio, todas las columnas | B. Aleatorio, sin identificadoras | C. Temporal, sin identificadoras |
|---|---|---|---|
| F1 macro | 0,3878 | 0,2264 | 0,0574 |
| Exactitud | 0,9848 | 0,8911 | 0,6988 |
| FP / 10k benignos | 20,0 | 597,7 | 676,8 |
| Columnas | 84 | 80 | 80 |

**Recall por clase** (las que tienen ejemplos suficientes para que la métrica
signifique algo):

| Clase | A | B | C |
|---|---|---|---|
| BENIGN | 0,9980 | 0,9402 | 0,9323 |
| DoS Hulk | 0,9867 | 0,8826 | **0,0000** |
| PortScan | 0,9388 | 0,8256 | **0,0000** |
| DDoS | 0,9955 | 0,3569 | **0,0000** |

### El resultado

**Lo firme es C.** Con el split temporal el modelo no detecta ni un solo
ataque de DoS Hulk, PortScan ni DDoS. Eso no cambió en ninguna de las corridas,
antes ni después de la auditoría, y tampoco cambia con la semilla del modelo:
con 10 semillas el recall de los tres es exactamente 0,0000 en todas (tabla de
dispersión, abajo). Cortado por día de captura —que es lo que ocurre en
producción, donde el ataque de mañana todavía no existe— no queda nada. El
recall de BENIGN se sostiene (0,93 con la semilla 42) porque el tráfico normal
sí se parece de un día para el otro. Lo que no generaliza son los ataques, que
es precisamente lo que un NIDS tiene que detectar.

**A y B no permiten concluir cuánto inflaban las columnas identificadoras.** Con
la semilla 42, A (con `Flow ID`, IPs y `Timestamp`) detecta entre el 94 % y el
99,6 % de cada ataque y B, sin esas columnas, entre el 36 % y el 88 %. Pero con
10 semillas los rangos de A y B se solapan por completo (tabla de dispersión,
abajo): la diferencia de la semilla 42 cabe dentro de lo que cambia el
resultado con solo cambiar la semilla. Con estos datos no se puede afirmar que
quitar las columnas identificadoras baje el rendimiento; lo que sí se puede
afirmar es que con un split aleatorio el recall de un mismo ataque puede ir de
0 a casi 1 según la semilla.

**B contra C** sigue mostrando que el split aleatorio sobreestima, pero con
otra forma: con split aleatorio el recall por ataque tiene una media de 0,61 a
0,71 y un rango de 0 a 0,99; con el temporal es 0 en todas las semillas.

### Dispersión con 10 semillas

Script: `benchmarks/cic_semillas.py` (semillas 1 a 10; la semilla cambia a la vez
el split aleatorio y el modelo). Los mismos 3.119.345 flujos. Media, desviación
estándar muestral, mínimo y máximo.

| | A: media ± desv. | A: rango | B: media ± desv. | B: rango | C: media ± desv. | C: rango |
|---|---|---|---|---|---|---|
| F1 macro | 0,262 ± 0,098 | 0,098–0,395 | 0,272 ± 0,132 | 0,111–0,464 | 0,060 ± 0,004 | 0,054–0,068 |
| FP / 10k benignos | 304 ± 319 | 25–844 | 286 ± 180 | 53–530 | 375 ± 509 | 34–1.545 |
| Recall BENIGN | 0,970 | 0,916–0,998 | 0,971 | 0,947–0,995 | 0,963 | 0,846–0,997 |
| Recall DoS Hulk | 0,774 ± 0,224 | 0,408–0,993 | 0,706 ± 0,303 | 0,139–0,976 | **0,000** | 0,000–0,000 |
| Recall PortScan | 0,821 ± 0,296 | 0,001–0,983 | 0,648 ± 0,414 | 0,000–0,984 | **0,000** | 0,000–0,000 |
| Recall DDoS | 0,643 ± 0,428 | 0,000–0,996 | 0,607 ± 0,406 | 0,000–0,989 | **0,000** | 0,000–0,000 |

Las cifras de la semilla 42 de la tabla de arriba caen dentro de estos rangos.
Que el F1 macro de A y de B sea indistinguible entre semillas no quiere decir que
las columnas identificadoras no importen: quiere decir que este experimento, con
este modelo, no tiene la precisión para medirlo. Con 10 semillas tampoco se
puede descartar un efecto menor.

### Por qué cambiaron A y B (y por qué no son cifras firmes)

Las cifras publicadas el 19/09 eran A: F1 0,1987 (recall de DoS Hulk 0,595) y
B: F1 0,3724 (recall de 0,93 a 0,98 en los tres ataques); de ahí salía la frase
"el modelo pasa de detectar entre el 93 % y el 98 % de cada ataque a no
detectar ni uno solo". Re-corrido el script en distintos puntos del historial,
sobre los mismos CSV y con las mismas versiones de LightGBM (4.7.0) y Polars
(1.44.2). Los hashes de la tabla son del historial original del proyecto, que no
se publica: aquí no se puede volver a correr el código de cada fila.

| Código | A: F1 | B: F1 | B: recall DDoS | C: F1 |
|---|---|---|---|---|
| Antes de `958ea86` (30/09) | 0,1987 | 0,3724 | 0,9596 | 0,0574 |
| `958ea86` | 0,3878 | 0,2264 | 0,3569 | 0,0568 |
| `35da75a` (antes de la auditoría) | 0,3878 | 0,2264 | 0,3569 | 0,0574 |
| `96c50e5` (1.0.0) | 0,3878 | 0,2264 | 0,3569 | 0,0574 |

Las cifras publicadas se reproducen exactas con el código anterior a
`958ea86` ("no convertir decimales tardíos en nulos"), y las de hoy aparecen
con ese commit. Las correcciones de la auditoría no las movieron. El
CHANGELOG de la 1.0.0 dice de ese cambio que "en CIC-IDS2017 no había ningún
nulo falso, así que los benchmarks ya publicados no cambian": para este
benchmark, no fue así.

Lo que cambió en los datos de entrada es mínimo: **9 valores de 3,1 millones de
filas**, todos en el archivo de infiltración del jueves (1 nulo menos en
`Total Length of Fwd Packets` y 8 en `Total Length of Bwd Packets`). Que eso
mueva el F1 de A de 0,20 a 0,39 y el recall de DDoS en B de 0,96 a 0,36 quiere
decir que **A y B son inestables**: con este modelo y estos parámetros, una
perturbación ínfima cambia por dónde corta el boosting. Es el mismo fenómeno que
Vigía existe para señalar —una métrica que parece un resultado y es un
artefacto—, encontrado en el benchmark de la propia herramienta.

C también oscila un poco entre commits que no deberían tocarlo (F1 entre 0,0568
y 0,0574, recall de BENIGN entre 0,9307 y 0,9323); el cero de los tres ataques
es estable en todas las corridas.

Esa inestabilidad se midió después con 10 semillas (sección "Dispersión con 10
semillas", arriba).

### Por qué el F1 macro es bajo en los tres

El dataset tiene 15 clases y varias con menos de 40 ejemplos (Heartbleed: 11,
SQL Injection: 21, Infiltration: 36). El F1 macro las promedia por igual, así
que ese puñado de clases domina la métrica y esconde el efecto que se quiere
medir. Es exactamente lo que advierte `labels.imbalance`: por eso la
comparación se hace sobre el recall por clase.

### Dos correcciones que hicieron falta para que el experimento midiera algo

**Las columnas categóricas tienen que entrar.** La primera versión solo usaba
columnas numéricas, así que `Source IP` —que es texto— nunca llegaba al modelo.
A y B daban idéntico y la comparación era vacía por construcción. Un pipeline
real codifica esas columnas, así que el benchmark también.

**Las 288.602 filas sin etiqueta rompen el entrenamiento.** Aparecieron al
arreglar el problema de codificación, y sin descartarlas el proceso falla al
ordenar las clases. Se descartan y se informa cuántas eran.

## Módulo 3: deriva entre los días de CIC-IDS2017

`benchmarks/cic_deriva_real.py`. Los cinco días son una serie temporal genuina:
la misma red y la misma instrumentación, días distintos. Cada día se compara
contra el lunes, que es enteramente benigno. 40.000 filas por lado.

| Comparación | Semáforo | AUC (`drift.covariate`) | Columnas con PSI alto |
|---|---|---|---|
| **Lunes barajado contra sí mismo** | **verde** | < 0,75 | **0** |
| Lunes mañana vs. lunes tarde | rojo | 0,873 | 51 |
| Martes vs. lunes | rojo | 0,816 | 16 |
| Miércoles vs. lunes | rojo | 0,801 | 42 |
| Jueves vs. lunes | rojo | 0,757 | 1 |
| Viernes vs. lunes | rojo | 0,840 | 31 |

El control negativo pasa limpio: dos muestras aleatorias del mismo día no
producen ningún hallazgo.

Medido antes de la 1.0.0, cuando el check adversario se llamaba
`drift.concept`; hoy es `drift.covariate`, y sus cifras no cambian. El
`drift.concept` de la 1.0.0 (que mide la relación con la etiqueta) no está en
esta tabla: como el lunes tiene una sola clase, se saltaría en todas las filas y
el control daría gris en vez de verde. Ver `docs/DERIVA.md`.

### El corte define la comparación

La primera mitad del lunes contra la segunda da **más deriva que martes contra
lunes** (AUC 0,873 contra 0,816). No es un fallo: los archivos vienen en orden
temporal, así que eso es la mañana contra la tarde, y el tráfico de oficina
cambia entre una y otra.

Importa en producción: un lote de "ayer" que abarca de las 14:00 a las 14:00
mezcla dos perfiles y produce deriva que nadie introdujo.

## Módulo 2: envenenamiento sobre CIC-IDS2017 real

`benchmarks/cic_envenenamiento_real.py`. Los mismos tres ataques del simulador,
pero inyectados sobre 30.000 flujos auténticos en vez de flujos generados.

| Ataque | Mejor detector | Precisión | Recall | F1 | F1 sintético |
|---|---|---|---|---|---|
| Puerta trasera | `poison.trigger` | 0,437 | 1,000 | **0,608** | 1,000 |
| Inyección sintética | `poison.loss` | 0,951 | 0,485 | **0,642** | 1,000 |
| Cambio de etiqueta | `poison.knn` | 0,621 | 0,478 | **0,540** | 1,000 |

**La medición sintética sobrestimaba el rendimiento por un margen enorme.** En
un dataset generado las clases están bien separadas y cualquier fila envenenada
sobresale; el tráfico real tiene colas largas y filas raras que no son
envenenamiento.

### La puerta trasera daba F1 0,007 por dos filtros

`Destination Port` tiene 4.931 valores distintos en 30.000 filas, y el detector
descartaba la columna entera por superar `n/10` valores únicos. El criterio
correcto no es cuántos valores distintos hay sino si el valor se repite.

El segundo era el límite de frecuencia global: una puerta trasera en
exactamente el 2 % de las filas da 2,0033 % cuando alguna fila ya tenía ese
valor, cruzaba el límite y desaparecía, mientras que al 1,5 % se detectaba con
recall 1,000.

| Ratio inyectado | Precisión | Recall |
|---|---|---|
| 0,5 % | 0,158 | 1,000 |
| 1,0 % | 0,273 | 1,000 |
| 1,5 % | 0,367 | 1,000 |
| 2,0 % | 0,437 | 1,000 |

Subir el umbral al 3 % parecía más simple y reintrodujo los falsos positivos
que ese límite existe para evitar. La holgura acotada del 10 % fue la única
forma de arreglar el borde sin romper lo demás. Costo: 844 falsos positivos en
el control limpio contra 259, el 2,8 % del dataset.

### `poison.cluster` no aporta nada sobre datos reales

Precisión y recall **0,000** en los dos ataques que fue diseñado para detectar,
marcando entre 1.755 y 2.171 filas de 30.000. Su `eps` en el percentil 10 solo
agrupa flujos casi idénticos —repeticiones normales del mismo servicio— y no
las filas inyectadas, que llevan jitter.

| Percentil de `eps` | Marcadas | Aciertos | Precisión | Recall |
|---|---|---|---|---|
| 10 (actual) | 1.755 | 0 | 0,000 | 0,000 |
| 25 | 3.460 | 2 | 0,001 | 0,003 |
| 50 | 10.164 | 11 | 0,001 | 0,018 |
| 75 | 10.009 | 154 | 0,015 | 0,257 |
| 90 | 13.655 | 297 | 0,022 | 0,495 |

No hay punto de operación útil, así que pesa cero en el puntaje combinado. El
detector sigue publicando su hallazgo por separado.

### Un defecto que solo aparecía con datos reales

`poison.trigger` marcaba **22.228 de 30.000 filas de un dataset limpio** (74 %).
Los tres límites del detector se aplicaban valor por valor, y `Total Fwd
Packets` aportaba los valores 13, 16, 17, 18, 20, 23, 24, 25 y 26: cada uno
rarísimo por separado —la masa está repartida entre cientos de valores— pero
juntos son la distribución normal de una variable de conteo. 884 candidatos así.

Con el límite de tres valores por columna baja a 259 filas (0,9 %).

El fixture sintético no lo mostraba, y reproducirlo en un test exigió las tres
condiciones juntas: volumen, varias columnas de conteo con cola larga, y medias
que difieren por clase.

## Módulo 2: ruido de etiqueta documentado por Engelen et al.

`benchmarks/cic_ruido_engelen.py`. **La única verdad de referencia que no
inyectamos nosotros.** La versión corregida marca con
`Attempted-relabel-as-Benign` los 8.966 flujos que el original daba por ataque
sin serlo. Se les devuelve la etiqueta `Benign` y se mide qué detector los
encuentra.

Con 0,46 % de filas ruidosas, el azar acierta el 0,46 % de las veces:

| Detector | Marcadas | Aciertos | Precisión | Contra el azar |
|---|---|---|---|---|
| `poison.trigger` | 499 | 44 | 0,088 | **19,2x** |
| `poison.cluster` | 744 | 26 | 0,035 | 7,6x |
| `poison.loss` | 300 | 9 | 0,030 | 6,5x |
| `poison.knn` | 98 | 1 | 0,010 | 2,2x |
| combinado (`min_detectors=2`) | 88 | 1 | 0,011 | 2,5x |

**Unión de los cuatro: 79 de 138 filas (57,2 % de recall).**

### La premisa de la coincidencia resultó ser condicional

| Par de detectores | Filas en común | De esas, mal etiquetadas |
|---|---|---|
| `cluster` & `knn` | 0 | 0 |
| `cluster` & `loss` | 0 | 0 |
| `cluster` & `trigger` | 0 | 0 |
| `knn` & `loss` | 76 | 1 |
| `knn` & `trigger` | 0 | 0 |
| `loss` & `trigger` | 12 | 0 |

`poison.cluster` **no comparte ni una fila** con los otros tres. Los detectores
encuentran cosas distintas, no la misma por caminos distintos.

La documentación afirmaba que "la coincidencia entre métodos independientes es
la señal". Se cumple sobre envenenamiento **inyectado**, donde una fila
envenenada es anómala de varias formas a la vez. No se cumple sobre ruido de
etiqueta **natural**, donde cada fila es rara de una sola forma: ahí exigir
coincidencia descarta casi todos los aciertos y el rendimiento cae de 19,2x a
2,5x.

Para buscar etiquetas mal puestas conviene `--min-detectors 1` y revisar la
lista de cada detector por separado.

## Auditorías sobre datasets reales de la lista R17

Medido el 30/09/2026 con `vigia audit --profile <perfil>`. Las cifras de esta
sección son las **corregidas** tras el defecto de inferencia de tipos descrito
al final: una primera pasada hecha antes del arreglo tenía conteos falsos de
`validity.nan_inf`, y el archivo del 20-02 de CSE-CIC-IDS2018 salía rojo con 15
hallazgos altos que no existían.

### CSE-CIC-IDS2018

Los 10 CSV de "Processed Traffic Data for ML Algorithms" (6,9 GB, 16,2 M de
filas en total), descargados del bucket público del dataset. Los 10 terminaron
sin errores, en 19 a 75 s cada uno. El de 20-02 (7,9 M de filas) corrió con
`--streaming`: solo ejecuta los checks de duplicados y validez, y el resto queda
listado como no ejecutado.

| Archivo | Filas | Semáforo | Crít. | Altos | Medios | Bajos |
|---|---|---|---|---|---|---|
| Wednesday-14-02 | 1.048.575 | rojo | 4 | 4 | 2 | 2 |
| Thursday-15-02 | 1.048.575 | rojo | 0 | 1 | 0 | 3 |
| Friday-16-02 | 1.048.575 | rojo | 10 | 1 | 4 | 1 |
| Tuesday-20-02 (streaming) | 7.948.748 | amarillo | 0 | 0 | 0 | 4 |
| Wednesday-21-02 | 1.048.575 | rojo | 11 | 1 | 1 | 2 |
| Thursday-22-02 | 1.048.575 | rojo | 0 | 3 | 1 | 3 |
| Friday-23-02 | 1.048.575 | rojo | 0 | 1 | 1 | 3 |
| Wednesday-28-02 | 613.104 | rojo | 1 | 1 | 3 | 2 |
| Thursday-01-03 | 331.125 | rojo | 1 | 2 | 2 | 1 |
| Friday-02-03 | 1.048.575 | rojo | 4 | 1 | 1 | 3 |

Hallazgos por check, sobre los 10 archivos: `dup.exact` en 10,
`shortcut.identifier` en 9 (el de `--streaming` no corre los checks de
atajos), `validity.nan_inf` en 8, `validity.constant` en 7,
`shortcut.single_feature` y `labels.imbalance` en 5 cada uno, `labels.noise` y
`dup.class_ratio` en 4, `labels.conflict` y `validity.impossible` en 2. De los
31 hallazgos críticos, 30 son atajos de una sola columna
(`shortcut.single_feature`) y 1 es `labels.conflict`. En el 14-02, por ejemplo,
`Dst Port` predice la etiqueta con 100 % de exactitud balanceada (ahí los
ataques son fuerza bruta sobre FTP y SSH) y `Fwd Seg Size Min` con 99,9 %.

**El amarillo del 20-02 no significa que ese archivo esté limpio.** Es el único
que se auditó en streaming, así que 10 checks no corrieron (atajos, ruido de
etiquetas, `leak.host`…). A diferencia de los otros nueve, ese CSV sí trae
`Flow ID`, `Src IP` y `Dst IP` (84 columnas en vez de 80): con memoria
suficiente valdría la pena auditarlo completo.

Lo que esta prueba no puede medir:

- **Sin split.** No hay columna de train/test, así que `dup.cross_split` y los
  checks de fuga no corren; en 9 de 10 archivos tampoco hay IPs.
- **`Timestamp` ambiguo.** Usa reloj de 12 horas sin AM/PM (Hulk aparece a las
  01:45 y la documentación dice 13:45), por eso el perfil no lo fija como
  `time_col`.
- **Archivos truncados.** 7 de los 10 CSV se cortan en 1.048.575 filas, el
  límite de Excel.
- **`dup.near`** por encima de 200.000 filas trabaja con una muestra (cota
  inferior); antes no corría.

Las ventanas del perfil, tomadas de la página del CIC, coinciden con los CSV en
casi todo (una vez considerado el reloj de 12 h), con cinco discrepancias que el
perfil registra en `known_issues`: Bot (02-03) está etiquetado durante todo el
día y no solo en sus dos ventanas; SQL Injection (22 y 23-02) son 34 y 53 filas
dispersas fuera de su ventana; el CSV del 20-02 no trae etiqueta LOIC-UDP; las
etiquetas tienen errores de tipeo (`Infilteration`, `DDOS attack-HOIC`); y los
nombres difieren de los de la tabla oficial.

### CSE-CIC-IDS2018, 20-02: los checks de fuga sobre datos reales

El 20-02 es el único archivo de CSE-CIC-IDS2018 que trae `Flow ID`, `Src IP`,
`Dst IP` y puertos (84 columnas). Pero los checks de fuga también necesitan una
columna de split, que ese archivo no tiene, así que tener IPs no alcanzaba. Se
auditó una muestra aleatoria de 1.000.000 de filas (de 7,9 M) con un split
aleatorio 80/20 **creado para esta prueba**, que es el que haría un usuario
típico. El resultado mide cuánta fuga produce ese tipo de split sobre este
tráfico, no un defecto del dataset:

| Check | Hallazgo |
|---|---|
| `leak.host` | **7.610 IPs de origen** y **6.543 de destino** aparecen en entrenamiento y en prueba |
| `leak.session` | **11.836 sesiones** (la 5-tupla) repartidas entre los dos lados |
| `shortcut.single_feature` | `Src IP` y `Dst IP` predicen la etiqueta con 100 % de exactitud balanceada |
| `leak.temporal` | 100 % de las filas de prueba son anteriores al fin del entrenamiento (esperable en un split al azar) |
| `shortcut.identifier` | 4 columnas: `Flow ID`, `Src IP`, `Dst IP`, `Timestamp` |
| `labels.noise` | 26 etiquetas (0,01 %) |

Es la primera vez que `leak.host` y `leak.session` corren sobre datos reales en
este proyecto. En esas capturas el ataque (DDoS LOIC-HTTP, 7,2 % de las filas)
sale de máquinas concretas, por lo que un modelo que vea la IP no aprende el
ataque. La auditoría de la muestra tardó 53 s. No se auditó el archivo completo
sin streaming: cargarlo ocupa 9,7 GB y no habría activado más checks.

### UNSW-NB15

Con los **archivos oficiales** de los autores (carpeta "CSV Files" de su
OneDrive), que coinciden con la página del dataset: training-set de 175.341
filas (56.000 normales, 119.341 ataques), testing-set de 82.332 (37.000 y
45.332) y cuatro CSV crudos que suman 2.540.044 filas según la página (Vigía lee
2.540.047). Los crudos **no traen cabecera**; el perfil `unsw-nb15-raw` les pone
los 49 nombres del diccionario oficial.

| Archivo | Filas | Semáforo | Hallazgos principales |
|---|---|---|---|
| training-set | 175.341 | rojo | `attack_cat` predice la etiqueta al 100 %; 87.050 casi-duplicados (6.097 grupos); 7,42 % de etiquetas dudosas |
| testing-set | 82.332 | rojo | `attack_cat` al 100 %; 36.890 casi-duplicados (3.960 grupos); 9,06 % de etiquetas dudosas |
| **train + test con split** (sin `id`) | 257.673 | rojo | **12.668 filas (4,9 %) aparecen en train y en test**; 36,84 % de duplicados exactos; 2,08 % de etiquetas dudosas |
| crudo 1 | 700.001 | rojo | 6 atajos críticos (`srcip` y `dstip` al 99,6 %) |
| crudo 2 | 700.001 | rojo | 8 atajos críticos |
| crudo 3 | 700.001 | rojo | 6 atajos críticos; 32,12 % de duplicados exactos |
| crudo 4 | 440.044 | rojo | 6 atajos críticos; 30,30 % de duplicados exactos |
| **los 4 crudos juntos** | 2.540.047 | rojo | `srcip` y `dstip` predicen la etiqueta con 99,1 %; 18,92 % de duplicados exactos |

Tiempos: training-set 10 min y testing-set 4 min (medidos antes de acelerar
`dup.near`, ver la sección de calibración), cada crudo
entre 11 y 36 s, los cuatro juntos 26 s.

- **Solape train/test.** Es el defecto conocido del dataset, medido con
  `dup.cross_split` sobre los archivos oficiales sin la columna `id` (es un
  índice que reinicia en cada archivo). `dup.exact` no marca nada en cada
  archivo por separado porque `id` es único; ignorándola, el training-set tiene
  67.601 filas duplicadas (38,6 %).
- **`attack_cat` filtra la respuesta.** Deriva de la etiqueta: usarla como
  característica da 100 % de exactitud.
- **Las IPs predicen la etiqueta.** En los crudos `srcip` y `dstip` dan 97,7 a
  99,6 % de exactitud balanceada; el GT registra solo 4 atacantes y 10
  víctimas.
- **Los faltantes son estructurales.** `is_ftp_login` y `ct_flw_http_mthd` están
  vacías en el 56 % y el 53 % de las filas porque no aplican a flujos que no
  son FTP ni HTTP; `validity.nan_inf` las marca igual. `sport` y `dsport` traen
  8 y 61 valores que no son puertos (`0x000b`, `-`), que Vigía lee como nulos.
- **No corren los checks de fuga** (`leak.host`, `leak.session`,
  `leak.temporal`): los crudos tienen IPs y `Stime`, pero ninguna columna de
  split.

**Cuidado con las réplicas de Hugging Face.** Antes de tener los oficiales se
auditó con réplicas, y dieron cifras distintas. La de `Mouwiya` del
training-set es idéntica al oficial (mismo SHA-256), pero sus archivos crudos
traen 2.280.090 filas, el 10 % menos. La de `wwydmanski` es el dataset oficial
con los decimales reducidos a `Float32` y **sin 9 columnas** (`id`, `sttl`,
`dttl` y varias `ct_*`), con los nombres train y test invertidos. Al faltar
columnas más filas parecen idénticas, y esa réplica daba un solape de 67.145
filas (26 %) que **era un artefacto**: con el dataset completo es de 12.668
(4,9 %). Conviene auditar siempre los archivos oficiales.

### CTU-13

Los 13 escenarios completos (4,9 GB, 20,0 M de flujos), de los README y los
`.binetflow` oficiales. Los 6 más chicos corrieron completos, sin `dup.near`, y
los 7 más grandes en `--streaming`. Todos dan rojo.

**La etiqueta se agrupa antes de auditar.** Los archivos traen decenas de
subtipos por escenario (60 en el 5), con lo que `labels.imbalance` y
`labels.noise` no significaban nada. El perfil `ctu-13` los agrupa por prefijo en
`botnet`, `to_botnet`, `normal` y `background` (clave `label_groups`) y deja la
original en `__label_original`. Una familia sin `From`/`To`
(`flow=Normal-V46-HTTP-windowsupdate`, de 1 a 24 flujos) aparece en 11 de los
13 escenarios y no está en la documentación.

| Esc. | Captura | Modo | Flujos | Semáforo | Crít. | Altos | Medios | Bajos |
|---|---|---|---|---|---|---|---|---|
| 1 | Botnet-42 | streaming | 2.824.636 | rojo | 0 | 5 | 0 | 3 |
| 2 | Botnet-43 | streaming | 1.808.122 | rojo | 0 | 5 | 0 | 3 |
| 3 | Botnet-44 | streaming | 4.710.638 | rojo | 0 | 5 | 3 | 0 |
| 4 | Botnet-45 | completo | 1.121.076 | rojo | 1 | 3 | 0 | 1 |
| 5 | Botnet-46 | completo | 129.832 | rojo | 1 | 3 | 0 | 1 |
| 6 | Botnet-47 | completo | 558.919 | rojo | 1 | 3 | 0 | 1 |
| 7 | Botnet-48 | completo | 114.077 | rojo | 1 | 3 | 1 | 1 |
| 8 | Botnet-49 | streaming | 2.954.230 | rojo | 0 | 5 | 3 | 0 |
| 9 | Botnet-50 | streaming | 2.087.508 | rojo | 0 | 5 | 0 | 3 |
| 10 | Botnet-51 | streaming | 1.309.791 | rojo | 0 | 5 | 0 | 3 |
| 11 | Botnet-52 | completo | 107.251 | rojo | 1 | 4 | 0 | 1 |
| 12 | Botnet-53 | completo | 325.471 | rojo | 1 | 3 | 0 | 1 |
| 13 | Botnet-54 | streaming | 1.925.149 | rojo | 0 | 5 | 3 | 0 |

- **`SrcAddr` predice la clase con 99,8 a 99,9 % de exactitud balanceada** en los
  6 escenarios que corrieron completos (el crítico de la tabla). Es esperable: el
  tráfico botnet sale de los hosts infectados, así que la IP de origen define la
  etiqueta. Con las 60 subetiquetas este atajo quedaba tapado. En los 7 de
  streaming no corren los checks de atajos, por lo que no se sabe.
- **`labels.noise` solo corrió en 1 de los 6.** En los demás el modelo auxiliar no
  supera a la clase mayoritaria (el 90 a 98 % del tráfico es "background"), así
  que el check se salta y lo dice. En el escenario 11 marca 1,27 %. El "13 a
  14 % de ruido" que mostraba la primera pasada en los escenarios 4 a 7 y 12 era
  un artefacto de los 60 subtipos.
- **Validación del perfil contra los datos:** en 11 de 13 escenarios los
  orígenes de los flujos `From-Botnet` son exactamente los hosts infectados que
  da el README. En el escenario 3 aparece además `38.229.70.20` (63 flujos) y en
  el 12 seis orígenes externos con 4 a 5 flujos cada uno. El tráfico botnet es
  entre 0,06 % y 8,9 % de los flujos y el "background" entre 89,7 % y 98,5 %.
- **`validity.nan_inf` sobre `SrcWin` y `DstWin`** son faltantes estructurales
  (los flujos que no son TCP no tienen ventana), no corrupción.
- **Tiempo:** los escenarios completos pasaron de 194 a 368 s con 60 clases a 21
  a 50 s con 4.

### UGR'16

**No se pudo auditar con datos oficiales:** `nesg.ugr.es` respondió 403 y luego
mostró una página de mantenimiento. Solo se usó una muestra de 5.000 filas de
`ugr16-july-week5` (copia de terceros) para confirmar el formato: CSV **sin
cabecera**, 13 columnas, etiqueta al final. Auditada con el perfil da amarillo
(247 casi-duplicados, una clase con 21 ejemplos), pero 5.000 filas de un solo
instante no permiten sacar conclusiones sobre el dataset.

### Un defecto de Vigía que solo aparecía con estos datos

El tipo de cada columna se infería con las primeras 10.000 filas. Si una columna
parecía entera ahí y más adelante traía decimales (`1249` al principio, `150.0`
después), `ignore_errors=True` los convertía en nulos **sin avisar**, y
`validity.nan_inf` los reportaba como datos corruptos: 55.796 valores falsos en
`Active Std` del 14-02 y 7,37 millones en `TotLen Fwd Pkts` del 20-02, que no
tienen ninguno. Corregido: las columnas enteras se leen como `Float64` y vuelven
a entero si todos sus valores lo son. Se midió el efecto sobre los 8 CSV de
CIC-IDS2017 y **no hay ningún nulo falso**, así que los resultados de este
documento sobre ese dataset no cambian.

Otros defectos que aparecieron al usar datos reales y ya están corregidos:
`--streaming` ignoraba `--profile`, Vigía no abría `.binetflow` y
`validity.impossible` se caía con columnas enteras chicas (`is_sm_ips_ports`).

## Control de falsos positivos y calibración

Todo lo anterior mide si Vigía encuentra problemas reales. Esta sección mide lo
contrario: si inventa problemas donde no los hay. Se usa un dataset sintético
sin ningún defecto sembrado (`benchmarks/control_limpio.py`): 100.000 flujos sin
duplicados, nulos ni columnas constantes, con split limpio por tiempo y por host
(origen y destino distintos en cada lado) y características que solo clasifican
bien en combinación.

### El control

| Variante | Semáforo | Qué marca |
|---|---|---|
| Con `timestamp`, `src_ip` y `dst_ip` **declarados** (`--time-col`, `--src-ip-col`, `--dst-ip-col`) | **verde** | nada |
| Con esas tres columnas solo **detectadas por nombre** | rojo | `shortcut.identifier` (alto) por esas tres columnas |
| Sin esas tres columnas | gris | nada, pero `leak.host`, `leak.session` y `leak.temporal` no pueden correr sin IPs ni tiempo |

Medido el 04/10/2026 con el código de la 1.0.0 sobre las 100.000 filas. Antes de
las dos decisiones de diseño de abajo, las dos primeras variantes daban rojo y
amarillo.

**Ningún check de duplicados, fuga, atajos de una columna, validez, desbalance o
conflicto de etiquetas inventó un problema** (hay un test que lo vigila:
`tests/unit/test_control_limpio.py`, y los de fuga corrieron y no encontraron
nada). El control antes **no podía dar verde**, por dos razones de diseño que se
resolvieron en la 1.0.0:

1. **Las columnas de rol contaban como características.**
   `shortcut.identifier` marcaba `timestamp`, `src_ip` y `dst_ip` aunque fueran
   metadatos que el usuario declaró para los checks de fuga. Ahora, lo que se
   declara (opción o perfil) no se marca y queda fuera del hash de duplicados;
   sigue disponible para `shortcut.single_feature` y los checks de fuga. Lo que
   solo se detecta por nombre se sigue marcando.
2. **`labels.noise` marcaba "medio" cualquier hallazgo**, incluso 12 filas de
   100.000 (0,01 %). Ahora no reporta por debajo del 0,1 % de filas (ver la
   calibración de abajo).

### Cuánto acierta `labels.noise`

Sobre el mismo generador, con 4 clases y ruido de etiqueta inyectado a propósito
(100.000 filas), variando cuánto se separan las clases y la forma de las
características:

| Separación de clases | Forma | Ruido real | Lo que marca |
|---|---|---|---|
| fuerte (2,5) | normal | 0 % | nada |
| fuerte (2,5) | cola larga | 0 % | 0,01 % |
| fuerte (2,5) | normal | 3,8 % | 3,2 % |
| fuerte (2,5) | cola larga | 3,8 % | 3,5 % |
| media (1,5) | normal | 0 % | 0,4 % |
| media (1,5) | cola larga | 0 % | 0,8 % |
| media (1,5) | normal | 3,8 % | 3,8 % |
| media (1,5) | cola larga | 3,8 % | 4,5 % |
| **baja (0,9, clases solapadas)** | normal | **0 %** | **6,2 %** |
| **baja (0,9, clases solapadas)** | cola larga | **0 %** | **7,9 %** |
| baja (0,9) | normal | 3,8 % | 8,8 % |
| baja (0,9) | cola larga | 3,8 % | 10,4 % |

Con clases razonablemente separables acierta casi exacto. Con clases muy
solapadas **sobreestima entre 6 y 8 puntos**: no puede distinguir una etiqueta
mala de un ejemplo que cae en la zona de solape entre dos clases. Es una
limitación del método (aprendizaje con confianza), no un error de implementación.
El hallazgo ya lo dice ("candidatas a revisión humana") y declara además una
cota de cuánto pudo sobreestimar según la exactitud del modelo auxiliar. Medida
con ruido inyectado (36 configuraciones de 50.000 filas), el máximo observado
fue 0,6 puntos con exactitud de 0,97 o más, 3,1 entre 0,90 y 0,97, 8,3 entre
0,80 y 0,90 y 14,8 por debajo. La exactitud sola no separa ruido de
solapamiento: con 0,88 se marca 6,35 % sin ruido real y 7,57 % con ruido de
8 %.

### Otros defectos que aparecieron al hacer esto

- **`cleanlab` lanzaba un pool de procesos** que, en Windows, relanzaba en
  cadena el script que usaba Vigía como librería sin la guarda
  `if __name__ == "__main__"` (25 procesos en una prueba). Corregido con
  `n_jobs=1`; además el test de `labels.noise` pasó de 44 a 5 s.
- **`dup.near` era lento.** Calculaba las firmas MinHash token por token. Con
  `MinHash.bulk`, que da exactamente las mismas firmas (hay un test), es 5 veces
  más rápido: 20.000 filas de 44 columnas pasan de 34 a 4 s en las firmas, y el
  testing-set de UNSW-NB15 (82.332 filas) de 153 a 31 s en total. El resultado es
  idéntico (36.890 filas en 3.960 grupos). Sigue limitado a 200.000 filas.

### Efecto de los roles declarados y del umbral en datos reales

Medido el 01/10/2026. Cada dataset se audita completo con su perfil (los roles de
tiempo e IPs quedan declarados) y se repite `dup.exact`, `dup.cross_split` y
`labels.conflict` sacando los roles del hash, para comparar el hash nuevo con el
anterior sobre los mismos datos.

| Dataset | Filas | Roles declarados | `dup.exact` antes | `dup.exact` ahora | `labels.conflict` |
|---|---|---|---|---|---|
| CTU-13, los 13 escenarios | 0,11 a 4,7 M | 3 | 0 | 0 | 0 |
| UNSW-NB15 crudo 1 | 700.001 | 3 | 59.213 | 59.342 | 0 |
| UNSW-NB15 crudo 2 | 700.001 | 3 | 63.248 | 63.378 | 0 |
| UNSW-NB15 crudo 3 | 700.001 | 3 | 224.843 | 224.944 | 0 |
| UNSW-NB15 crudo 4 | 440.044 | 3 | 133.325 | 133.388 | 0 |
| UNSW-NB15 train+test | 257.673 | 0 (el perfil no declara IPs) | 94.928 | 94.928 | 0 |
| CSE-CIC-IDS2018 20-02 (muestra de 300.000) | 300.000 | 3 | 0 | 6 (más 2 en `dup.cross_split`) | 0 |

- **Ignorar la IP y la hora no inventa conflictos de etiqueta:** `labels.conflict`
  da cero con el hash nuevo y con el anterior en todos los datasets (el check
  corre, no se salta). En los crudos de UNSW-NB15 aparecen entre 63 y 130
  duplicados exactos más, el 0,1 a 0,2 % de lo que ya se encontraba.
- **El umbral de 0,1 % de `labels.noise`** deja en el cuadro: CTU-13 51 (1,75 %) y
  52 (1,27 %), y UNSW-NB15 train+test (2,08 %). Calla el resto de CTU-13, los
  crudos 1 y CSE-2018. Los crudos 2, 3 y 4 de UNSW-NB15 quedan en 0,18, 0,11 y
  0,15 %, justo por encima del umbral.
- **Los 13 escenarios de CTU-13 corrieron completos, sin streaming**, en 11 a
  66 s cada uno (el mayor, 4,7 M de filas). Antes los 7 más grandes solo se
  auditaban en streaming.

## Pendientes

- **UGR'16** con archivos oficiales: confirmar los nombres de columna del perfil
  y auditar un archivo del test set y uno de calibración. El 01/10/2026 se
  revisaron las demás fuentes y ninguna trae flujos: el repositorio
  `josecamachop/UGR16_FeatureData` son agregados de un minuto, el conjunto de
  IEEE DataPort son tensores (y pide suscripción), y la página de CODAS solo
  remite a ese repositorio. Los flujos solo están en `nesg.ugr.es`, que sigue
  dando 403.
