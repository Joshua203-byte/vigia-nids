# Vigía

**Control de calidad continuo para los datos de modelos de ciberseguridad.**

Vigía revisa los datasets con los que se entrenan los detectores de intrusiones y
responde una pregunta incómoda: *¿este 0.99 de F1 es real, o es un artefacto de
los datos?*

La investigación sobre los datasets más usados del área (CIC-IDS2017,
CSE-CIC-IDS2018, UGR'16) documenta duplicados masivos, etiquetas incorrectas,
fugas entre entrenamiento y prueba, y columnas que le delatan la respuesta al
modelo. El resultado es siempre el mismo: **el modelo parece excelente en el
laboratorio y falla en una red real.**

> Estado: **v1.0.3 — los tres módulos implementados y
> validados contra datos reales.** El auditor cubre los requisitos P0 (R1 a R10)
> con cuatro salvedades —R5, R6, R7 y R8, más `labels.window`—, que están
> descriptas en "Límites conocidos" de [`docs/PLAN.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/PLAN.md); además trae
> los lectores de Zeek, Suricata EVE y PCAP (R13 y R14), una API REST, un panel
> web y una imagen Docker. Cuatro de los cinco checks del monitor de deriva
> están medidos sobre los cinco días de CIC-IDS2017 (`drift.concept`, rehecho
> antes de publicar, solo está calibrado con datos sintéticos), los detectores
> de envenenamiento sobre ataques inyectados en
> ese mismo tráfico y sobre el ruido de etiqueta que documentaron Engelen et
> al., y el auditor sobre los 10 archivos (16,2 M de filas) de CSE-CIC-IDS2018.
> Los números están en [`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md),
> incluidos los casos donde el rendimiento es pobre. Los límites conocidos y lo
> que queda pendiente: [`docs/PLAN.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/PLAN.md).

## Los tres módulos

| Módulo | Comando | Qué responde |
|---|---|---|
| **1. Auditor** | `vigia audit` | ¿Este dataset tiene defectos que inflen las métricas? |
| **2. Envenenamiento** | `vigia poison` | ¿Alguien insertó registros para manipular el modelo? |
| **3. Deriva** | `vigia drift` | ¿El tráfico de hoy sigue pareciéndose al de entrenamiento? |

25 checks (16 del auditor, 4 de envenenamiento y 5 de deriva), 8 correcciones
automáticas y la comparación de rendimiento antes/después.

## Instalación

```bash
pip install vigia-nids                # núcleo: CLI, lectores y la mayoría de los checks
pip install -e ".[dev]"                # o, desde el repositorio
vigia --help
```

Requiere Python 3.11 o superior. Hay extras opcionales según lo que se necesite:

| Extra | Qué agrega |
|---|---|
| `[ml]` | `labels.noise` (cleanlab), `dup.near` (datasketch), `poison.loss`, `poison.knn`, `poison.cluster`, `drift.covariate` y `drift.concept` (scikit-learn), y la comparación antes/después (LightGBM) |
| `[parquet]` | Instala `pyarrow`. No hace falta para leer ni escribir `.parquet`: Polars lo hace sin él |
| `[api]` | API REST y panel web (`vigia serve`) |
| `[pcap]` | Extraer flujos de un PCAP (NFStream) |

Sin `[ml]`, los checks que lo necesitan no fallan: quedan en "checks no ejecutados"
con el comando para instalarlo.

## Uso

```bash
# Auditar un dataset (las columnas se detectan solas por nombre)
vigia audit data/flows.csv --report out/

# Usar el perfil de un dataset conocido (fija las columnas por vos)
vigia audit data/cic2017.csv --profile cic-ids-2017

# Indicar las columnas explícitamente
vigia audit data/flows.parquet \
  --label-col Label --split-col split --time-col Timestamp \
  --src-ip-col "Src IP" --dst-ip-col "Dst IP" \
  --report out/

# Correr solo una categoría de checks
vigia audit data/flows.csv --checks leak,dup

# En CI: salir con código 1 si hay hallazgos críticos
vigia audit data/train.csv --fail-on critical

# Listar los checks disponibles
vigia checks
```

Desde Python:

```python
import vigia

ctx = vigia.load("data/flows.parquet", label_col="Label", split_col="split")
report = vigia.audit(ctx)

print(report.traffic_light())  # 'rojo' | 'amarillo' | 'verde' | 'gris'
print(report.counts())  # {'critical': 2, 'high': 1, ...}

from vigia.report import write_report

write_report(report, "out/")  # report.html + report.json
```

## Perfiles de datasets conocidos

`--profile` (o `vigia.load(..., profile=...)`) carga los metadatos verificados
de un dataset público: columnas de etiqueta, tiempo e IPs, atacantes y ventanas
de ataque documentados, y errores conocidos. Una columna pasada a mano siempre
gana sobre el perfil.

| Perfil | Dataset | Qué trae |
|---|---|---|
| `cic-ids-2017` | CIC-IDS2017 | columnas, 14 ventanas de ataque, errores conocidos |
| `cse-cic-ids-2018` | CSE-CIC-IDS2018 | columnas (confirmadas en los CSV), 22 ventanas, etiquetas reales, problemas observados |
| `unsw-nb15` | UNSW-NB15 (training y testing) | etiquetas, 9 categorías, atacantes, víctimas y jornadas de captura del GT oficial |
| `unsw-nb15-raw` | UNSW-NB15 (4 CSV crudos) | los 49 nombres de columna, porque esos archivos no traen cabecera |
| `ugr-16` | UGR'16 | calendario de ataques, capturas, IPs anonimizadas, etiquetas |
| `ctu-13` | CTU-13 | 13 escenarios con malware, hosts infectados y duración; formato de etiquetas |

Cada valor sale de la documentación oficial del dataset; lo que la fuente no
publica no se inventa. Tres advertencias:

- `ugr-16`: el formato (CSV sin cabecera, 13 columnas) se confirmó solo sobre
  una muestra de 5.000 filas de terceros, porque el sitio oficial no estaba
  disponible; los nombres de columna son los del paper y `label` es una
  convención del perfil.
- `cse-cic-ids-2018`: el `Timestamp` usa reloj de 12 horas sin AM/PM, por eso el
  perfil no lo fija como columna de tiempo.
- `ctu-13`: la etiqueta tiene decenas de subtipos por escenario, así que el
  perfil la agrupa en botnet, to_botnet, normal y background (`label_groups`) y
  deja la original en `__label_original`. Un perfil propio puede hacer lo mismo.

`vigia audit` muestra los errores conocidos del perfil al correr. Los
resultados de auditar estos datasets están en
[`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md).

## API y panel web

```bash
pip install -e ".[api]"
export VIGIA_API_KEY="una-clave-larga-y-al-azar"
vigia serve                      # API en http://localhost:8000

# o, con el panel incluido, en un solo contenedor:
VIGIA_API_KEY=una-clave docker compose up --build
```

Sin `VIGIA_API_KEY` la API corre **sin autenticación**: no la dejes así fuera de
una máquina de desarrollo (con `VIGIA_ENV=production` se niega a arrancar). Para
ponerla en un servidor con HTTPS, mirá [`docs/DESPLIEGUE.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/DESPLIEGUE.md). La API solo acepta CSV y Parquet (un PCAP recibe
415), limita el tamaño de subida, borra el dataset al terminar el trabajo y en
Docker corre como usuario sin privilegios. Referencia completa en
[`docs/USO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/USO.md#api-rest).

## Qué revisa hoy

| Check | Qué encuentra |
|---|---|
| `dup.exact` | Filas idénticas: el modelo se evalúa con ejemplos que ya vio |
| `dup.class_ratio` | Clases formadas mayoritariamente por duplicados |
| `dup.cross_split` | **Crítico.** La misma fila en entrenamiento y en prueba |
| `dup.near` | Filas casi idénticas que `dup.exact` no ve (MinHash); sobre 200.000 filas revisa una muestra |
| `leak.temporal` | El conjunto de prueba se solapa con el de entrenamiento en el tiempo |
| `leak.host` | El mismo host atacante en ambos splits: el modelo memoriza la IP |
| `shortcut.single_feature` | Una sola columna predice la etiqueta demasiado bien |
| `shortcut.identifier` | IPs, IDs de flujo o timestamps usados como características |
| `validity.nan_inf` | NaN e infinitos (CIC-IDS2017 los tiene en las columnas de tasas) |
| `validity.constant` | Columnas con un solo valor |
| `validity.impossible` | Puertos > 65535, duraciones negativas, bytes negativos |
| `validity.column_names` | Nombres con espacios (`" Destination Port"`) o ambiguos |
| `leak.session` | Flujos de la misma conexión repartidos entre splits |
| `labels.conflict` | Filas idénticas con etiquetas distintas |
| `labels.noise` | Etiquetas que contradicen al resto del dataset (cleanlab); no reporta por debajo del 0,1 % y declara cuánto pudo sobreestimar |
| `labels.taxonomy` | La misma clase escrita de varias formas |
| `labels.imbalance` | Clases con tan pocos ejemplos que su métrica no dice nada |

**Columnas de rol.** El tiempo y las IPs que declares (con `--time-col`,
`--src-ip-col`, `--dst-ip-col` o con un perfil) se tratan como metadatos:
`shortcut.identifier` no las marca y no cuentan para decidir si dos filas son
duplicadas, así que el mismo flujo visto desde otra IP u otra hora se detecta
como duplicado. Siguen disponibles para `shortcut.single_feature` y los checks de
fuga, que son los que encuentran una IP que delata la etiqueta. Las columnas que
solo se detectan por nombre se tratan como posibles identificadores.

Cada hallazgo trae severidad, métrica, filas afectadas, ejemplos concretos y una
recomendación. Un check que no puede correr (falta la columna de split, por
ejemplo) no falla en silencio: aparece en la sección "checks no ejecutados" del
reporte.

### El semáforo

| Color | Significa |
|---|---|
| **rojo** | Hay hallazgos críticos o altos, o algún check falló por un error interno |
| **amarillo** | Hay hallazgos medios o bajos |
| **verde** | Sin hallazgos y todos los checks se ejecutaron |
| **gris** | Sin hallazgos, pero algunos checks no se ejecutaron |

El gris existe porque "no encontré nada" y "está limpio" no son lo mismo. Si la
columna de etiqueta o la de split no se detectan, los checks que se saltan son
justamente los que buscan fuga y duplicados entre conjuntos: dar verde ahí sería
confirmar que el dataset está bien cuando en realidad casi no se lo revisó. Si el
semáforo da gris, especificá las columnas a mano con `--label-col` y `--split-col`.

## Corregir

Los hallazgos nombran su corrección. `vigia fix` las aplica:

```bash
# Ver las disponibles
vigia fixes

# Aplicarlas en cadena; el archivo original nunca se toca
vigia fix data/flows.csv \
  --apply drop_duplicates,drop_constant,drop_identifiers \
  --out data/flows_corregido.parquet
```

Las filas con etiqueta dudosa **nunca se borran**: `quarantine_noise` las deja
en un archivo aparte para que una persona las revise.

## Medir cuánto del rendimiento era real

```python
from vigia.benchmark import compare

c = compare(ctx, ["drop_identifiers"])
print(c.summary())
print(c.after.per_class_recall)
```

Entrena el mismo modelo antes y después de corregir. Una caída no significa
que las correcciones empeoraron el modelo: significa que el número original
estaba inflado. Sobre CIC-IDS2017, cambiar un split aleatorio por uno temporal
lleva el recall de DoS Hulk, PortScan y DDoS de un valor que, con el split aleatorio,
oscila entre 0 y casi 1 según la semilla, a **0,00 en las 10 semillas** — ver
[`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md).

## Formatos de entrada

| Formato | Extensión | Notas |
|---|---|---|
| CSV | `.csv`, `.txt` | Reintenta en cp1252 si no es UTF-8 |
| Parquet | `.parquet`, `.pq` | Conserva los tipos |
| Zeek | `.log` | TSV con cabecera o JSON Lines |
| Suricata EVE | `.json`, `.eve` | `--event-type` elige flujos o alertas |
| PCAP | `.pcap`, `.pcapng`, `.cap` | Con `pip install 'vigia-nids[pcap]'` |

Archivo suelto o carpeta completa: los datasets CIC vienen partidos en un
archivo por día, Vigía los concatena y conserva la procedencia en
`__source_file`. Los PCAP se leen de a uno, porque extraer flujos tarda minutos.

Detalles de cada formato en [`docs/USO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/USO.md#formatos-de-entrada).

## Desarrollo

```bash
pip install -e ".[dev,ml]"

pytest                 # pruebas
ruff check src tests   # lint
ruff format src tests  # formato
mypy src               # tipos
```

Agregar un check nuevo es una clase con cuatro atributos y un método. El
registro es automático al importarse el módulo desde `vigia/checks/__init__.py`.
Los detalles están en [`docs/ARQUITECTURA.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/ARQUITECTURA.md).

## Documentación

| Documento | Para qué |
|---|---|
| [`docs/CHECKS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/CHECKS.md) | Qué significa cada hallazgo del auditor y qué hacer |
| [`docs/ENVENENAMIENTO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/ENVENENAMIENTO.md) | Módulo 2: los detectores, el simulador y qué tan bien funcionan |
| [`docs/DERIVA.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/DERIVA.md) | Módulo 3: los checks, las métricas y cómo leerlos |
| [`docs/USO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/USO.md) | Referencia de la CLI, del SDK y del formato JSON |
| [`docs/DESPLIEGUE.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/DESPLIEGUE.md) | Poner la API y el panel en un servidor: Caddy, variables, qué vigilar y los límites conocidos |
| [`docs/ARQUITECTURA.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/ARQUITECTURA.md) | Cómo está armado por dentro; cómo agregar un check |
| [`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md) | Resultados verificados: NSL-KDD, CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, CTU-13, el control de falsos positivos y la calibración |
| [`docs/PLAN.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/PLAN.md) | Estado, límites conocidos, lo que queda pendiente y el plan original por fases |
| [`AUDITORIA-1.0.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/auditoria-1.0/AUDITORIA-1.0.md) | La auditoría previa a la 1.0: 50 hallazgos, cómo se reprodujeron y cómo se corrigió cada uno |
| [`VERIFICACION-1.0.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/auditoria-1.0/VERIFICACION-1.0.md) | La verificación de esas correcciones y lo que encontró. La hizo la misma sesión de Claude que escribió las correcciones: no es independiente |

## Documento de diseño

El diseño completo — los tres módulos (auditor, envenenamiento, deriva), la
arquitectura, el plan por fases y las referencias académicas — está en
[`vigia.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia.md).

## Contribuir y seguridad

Los reportes más útiles son los hallazgos equivocados: un falso positivo o un
defecto real que Vigía no vio sobre un dataset público. Hay una plantilla para
eso en los [issues](https://github.com/Joshua203-byte/vigia-nids/issues/new/choose).
Cómo armar el entorno y las convenciones del proyecto:
[`CONTRIBUTING.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/CONTRIBUTING.md).
Para reportar una vulnerabilidad, no abras un issue público: ver
[`SECURITY.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/SECURITY.md).

## Licencia

Apache 2.0.
