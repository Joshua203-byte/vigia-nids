# VIGÍA
## Control de calidad continuo para los datos de modelos de ciberseguridad

> Documento maestro del proyecto: visión, problema, producto, arquitectura, tecnologías, plan de trabajo, modelo de negocio y riesgos.
> Versión 0.1 · Septiembre 2026 · Autor: Joshua (estudiante de Ingeniería en Ciencias de la Computación Integradas)

*"Vigía" es un nombre de trabajo; se puede cambiar sin afectar nada del diseño.*

> **Nota (octubre de 2026).** Este es el documento de diseño original, escrito
> antes de la primera línea de código, y se deja como se escribió: incluye el
> plan de negocio, los riesgos y los primeros pasos tal como se pensaron en ese
> momento. No describe el estado actual. Lo que está hecho, lo que cambió y lo
> que falta está en [`vigia/docs/PLAN.md`](vigia/docs/PLAN.md); los resultados
> medidos, en [`vigia/benchmarks/RESULTADOS.md`](vigia/benchmarks/RESULTADOS.md).

---

## Índice

1. Resumen ejecutivo
2. El problema
3. La solución: tres módulos
4. Usuarios y casos de uso
5. Objetivos y no-objetivos
6. Requisitos (P0 / P1 / P2)
7. Arquitectura del sistema
8. Módulo 1 — Auditor de datasets
9. Módulo 2 — Detector de envenenamiento
10. Módulo 3 — Monitor de deriva
11. Formatos de entrada y normalización
12. Selección de tecnologías
13. Modelo de datos
14. API y CLI
15. Reportes y experiencia de usuario
16. Cómo validar que funciona
17. Seguridad y privacidad de la propia herramienta
18. Estructura del repositorio
19. Plan de trabajo por fases
20. Modelo de negocio
21. Competencia y diferenciación
22. Riesgos y mitigaciones
23. Métricas de éxito
24. Habilidades a desarrollar
25. Primeros pasos concretos
26. Preguntas abiertas
27. Referencias
28. Glosario

---

## 1. Resumen ejecutivo

**Vigía** es una plataforma que vigila los datos de los modelos de ciberseguridad durante toda su vida:

- **Antes de entrenar**, detecta errores como etiquetas mal puestas, información filtrada entre entrenamiento y prueba, o columnas (IPs, puertos, tiempos) que le "delatan" la respuesta al modelo.
- **Durante el entrenamiento**, identifica datos envenenados a propósito por atacantes para que el modelo ignore sus ataques.
- **En producción**, avisa cuando los ataques cambian y el modelo empieza a quedarse desactualizado.

**Frase de una línea:** Vigía asegura que un detector de intrusiones aprenda con datos confiables y siga funcionando cuando los atacantes cambian de estrategia.

**Por qué ahora:** cada vez más productos de seguridad (NIDS, EDR, filtros de phishing, detección de fraude) usan machine learning, pero la investigación muestra que los datos con los que se entrenan y evalúan suelen tener fallas graves que inflan los resultados. No existe (según la búsqueda realizada) una herramienta especializada que cubra estas tres etapas para el dominio de seguridad.

**Tipo de problema:** principalmente **limpieza y ordenamiento de datos**, con un componente de análisis para demostrar el impacto (cuánto cambia el rendimiento real del modelo).

---

## 2. El problema

### 2.1 Qué pasa

Los modelos de detección de intrusiones y malware se entrenan con datasets públicos o internos. Esos datasets tienen tres tipos de fallas:

1. **Errores accidentales en los datos.** Etiquetas incorrectas, flujos mal construidos, duplicados, huecos de captura.
2. **Contaminación intencional (envenenamiento).** Un atacante puede introducir registros falsos para que el modelo aprenda que su tráfico es normal.
3. **Envejecimiento (deriva).** Los atacantes cambian de técnica; el modelo entrenado con datos de hace un año deja de reconocer los ataques nuevos.

El resultado es el mismo en los tres casos: **el modelo parece excelente en el laboratorio y falla en una red real.**

### 2.2 Evidencia

| Hallazgo | Fuente | Nivel |
|---|---|---|
| CICIDS2017, uno de los datasets más usados, tiene problemas en la generación de tráfico, construcción de flujos, extracción de características y etiquetado. | Engelen, Rimmer, Joosen (2021), IEEE SPW | Fuerte |
| Se han cuantificado tasas de etiquetas corruptas de 6.67% en CIC-IDS2017 y 7.53% en CSE-CIC-IDS2018, con algunas clases de ataque por encima del 75%. | Cantone et al. (citado en literatura reciente) | Media (verificar fuente original) |
| Errores en todo el ciclo de creación de CIC-IDS-2017 y CSE-CIC-IDS-2018: orquestación de ataques, generación de características, documentación y etiquetado. | Liu et al. (2022), IEEE CNS | Fuerte |
| Se han identificado desorden de paquetes, flujos duplicados, huecos de captura no documentados y errores de etiquetado que cambian materialmente el rendimiento de detección. | Lanvin et al. (2023) | Media |
| En 30 papers de conferencias top de seguridad, el sesgo de muestreo aparece al menos parcialmente en 90% y el *data snooping* en 73%. | Arp et al. (2022), USENIX Security | Fuerte |
| En UGR'16, ataques tipo botnet no fueron identificados durante el etiquetado del subconjunto de entrenamiento; los datasets pueden contaminarse de forma accidental o deliberada. | Estudio publicado en PMC (2024) sobre datasets contaminados para NIDS | Media |
| Los clasificadores de malware sufren sesgo experimental en espacio y tiempo; evaluar sin respetar el orden temporal infla los resultados. | Pendlebury et al. (2019), TESSERACT, USENIX Security | Fuerte |
| Modelos que "aciertan" por atajos en vez de por la señal real fallan al cambiar de entorno (ejemplo en imagen médica, mismo fenómeno). | DeGrave, Janizek, Lee (2021), Nature Machine Intelligence | Fuerte (analogía de otro dominio) |

### 2.3 A quién afecta

- Empresas que venden productos de seguridad con ML (NIDS, EDR, XDR, anti-phishing, anti-fraude).
- Equipos internos de seguridad (SOC) que entrenan sus propios modelos.
- Investigadores y estudiantes que publican resultados sobre datasets defectuosos.
- Indirectamente, cualquier organización protegida por esos modelos.

### 2.4 Costo de no resolverlo

- Falsos negativos: ataques reales que pasan sin alerta.
- Falsos positivos: fatiga de alertas en el SOC.
- Decisiones de compra basadas en métricas infladas.
- Investigación académica que no se puede reproducir.

---

## 3. La solución: tres módulos

```
            ┌────────────────────────────────────────────────────────┐
            │                        VIGÍA                           │
            │                                                        │
 Dataset ──▶│  [1] AUDITOR  ──▶ [2] ENVENENAMIENTO ──▶  Modelo listo │
            │   (antes de       (durante el                          │
            │    entrenar)       entrenamiento)                      │
            │                                                        │
 Tráfico ──▶│  [3] MONITOR DE DERIVA  ──▶  Alertas / reentrenar      │
 en vivo    │   (en producción)                                      │
            └────────────────────────────────────────────────────────┘
```

| Módulo | Pregunta que responde | Momento | Salida |
|---|---|---|---|
| 1. Auditor | ¿Estos datos tienen errores que inflan mis resultados? | Antes de entrenar | Reporte de hallazgos + dataset corregido |
| 2. Envenenamiento | ¿Alguien metió datos falsos a propósito? | Al preparar/actualizar el set de entrenamiento | Lista de registros sospechosos con puntaje |
| 3. Deriva | ¿Mi modelo sigue viendo el mismo mundo con el que aprendió? | Continuamente en producción | Alertas, tablero, recomendación de reentrenar |

**Idea central:** los tres módulos comparten el mismo núcleo (ingesta, normalización, perfil estadístico del dataset "de referencia"), así que construir uno facilita los otros.

---

## 4. Usuarios y casos de uso

### 4.1 Personas

**P1 — Ingeniera de ML en una empresa de seguridad ("Ana").**
Entrena el detector de intrusiones del producto. Necesita confiar en sus métricas antes de un lanzamiento.

**P2 — Analista de SOC con modelos propios ("Carlos").**
Tiene un modelo de anomalías sobre logs de su red. No es experto en ML; quiere saber cuándo el modelo dejó de servir.

**P3 — Investigador o estudiante ("Luis").**
Publica papers de detección. Quiere evitar que un revisor le diga que su dataset tiene fugas.

**P4 — Responsable de riesgo / auditor externo ("Marta").**
Debe evaluar si un modelo de seguridad es confiable antes de comprarlo o certificarlo.

### 4.2 Historias de usuario

**Ana (P1)**
- Como ingeniera de ML, quiero auditar mi dataset antes de entrenar para no reportar métricas infladas por duplicados o fugas.
- Como ingeniera de ML, quiero ver qué columnas funcionan como atajo para eliminarlas antes de entrenar.
- Como ingeniera de ML, quiero detectar registros envenenados cuando incorporo datos de clientes o de fuentes externas.
- Como ingeniera de ML, quiero ejecutar la auditoría en mi pipeline de CI para que ningún modelo se entrene con datos sin revisar.

**Carlos (P2)**
- Como analista de SOC, quiero una alerta cuando el tráfico actual se aleje del de entrenamiento para saber cuándo el modelo pierde validez.
- Como analista de SOC, quiero una explicación en lenguaje simple de qué cambió (qué protocolos, qué puertos, qué horarios).

**Luis (P3)**
- Como investigador, quiero correr un comando sobre CICIDS2017 y obtener un reporte reproducible que pueda citar en mi paper.
- Como investigador, quiero comparar el rendimiento de mi modelo con el dataset original y con el corregido.

**Marta (P4)**
- Como auditora, quiero un reporte firmado con fecha y versión del dataset para documentar que el modelo fue evaluado correctamente.

### 4.3 Caso de uso completo (ejemplo)

1. Ana sube `flows_2026Q3.parquet` (4 millones de flujos) con `vigia audit`.
2. Vigía detecta: 11% de flujos duplicados; la columna `src_ip` predice la etiqueta con 98% de precisión (atajo); 3,200 flujos de un mismo ataque aparecen tanto en entrenamiento como en prueba.
3. Ana aplica las correcciones sugeridas; su F1 baja de 0.99 a 0.87, **que es el número real**.
4. Al integrar datos nuevos de un cliente, `vigia poison-scan` marca 450 registros "benignos" que se parecen demasiado a un ataque conocido.
5. En producción, `vigia monitor` muestra que la distribución de puertos de destino cambió un 40% en dos semanas y recomienda reentrenar.

---

## 5. Objetivos y no-objetivos

### 5.1 Objetivos

1. Detectar al menos el 80% de los errores conocidos y documentados en CICIDS2017 (usando como referencia las correcciones publicadas) en la versión 1.0.
2. Mostrar, para cada dataset auditado, la diferencia entre el rendimiento "aparente" y el "real" de un modelo base.
3. Detectar registros envenenados inyectados artificialmente con precisión y recall superiores a los de un detector de anomalías genérico (línea base).
4. Emitir alertas de deriva antes de que el rendimiento del modelo caiga más de un umbral configurable (por ejemplo, 5 puntos de F1).
5. Que un usuario nuevo pueda auditar un dataset en menos de 10 minutos desde la instalación.

### 5.2 No-objetivos (fuera de alcance en v1)

- **No es un IDS.** Vigía no detecta ataques en la red; revisa los datos de los modelos que sí lo hacen.
- **No es un limpiador genérico de CSV.** Solo se optimiza para datos de seguridad (flujos, logs, telemetría de endpoints).
- **No entrena el modelo del cliente.** Entrena modelos auxiliares solo para diagnosticar.
- **No es un SIEM ni un normalizador de logs completo.** Lee formatos comunes pero no reemplaza herramientas de ingesta.
- **No cubre ataques adversariales en inferencia** (evasión) en v1; solo envenenamiento en entrenamiento.

---

## 6. Requisitos

### 6.1 P0 — Imprescindibles (MVP)

| ID | Requisito | Criterio de aceptación |
|---|---|---|
| R1 | Leer CSV y Parquet de flujos de red | Dado un CSV de CICIDS2017, cuando se ejecuta `vigia audit`, entonces el archivo se carga sin errores y se muestra su esquema |
| R2 | Detectar duplicados exactos y casi-duplicados | Reporta el porcentaje de duplicados y cuántos cruzan entre entrenamiento y prueba |
| R3 | Detectar valores inválidos (NaN, infinitos, negativos imposibles, columnas constantes) | Cada problema aparece con columna, cantidad y ejemplo |
| R4 | Detectar conflictos de etiqueta (mismas características, distinta etiqueta) | Lista los grupos en conflicto |
| R5 | Detectar atajos (columnas que predicen la etiqueta sospechosamente bien) | Para cada columna, reporta la precisión de un modelo entrenado solo con ella y marca las que superan el umbral |
| R6 | Detectar fuga temporal y por sesión | Si el split no respeta el tiempo o separa flujos de la misma sesión, lo reporta |
| R7 | Detectar etiquetas probablemente incorrectas | Lista de registros sospechosos con puntaje de confianza |
| R8 | Generar reporte HTML y JSON | El reporte abre en navegador y el JSON valida contra un esquema |
| R9 | Comparar rendimiento antes y después de corregir | Muestra métricas del modelo base con dataset original y corregido |
| R10 | CLI instalable con `pip` | `pip install vigia` y `vigia --help` funcionan en Linux, macOS y Windows |

### 6.2 P1 — Importantes (siguiente versión)

| ID | Requisito |
|---|---|
| R11 | Módulo de envenenamiento con al menos tres detectores (por pérdida, por vecinos, por clustering) |
| R12 | Monitor de deriva por lotes (comparar un archivo nuevo contra la referencia) |
| R13 | Leer logs de Zeek y Suricata (EVE JSON) |
| R14 | Convertir PCAP a flujos con un extractor confiable |
| R15 | API REST y panel web |
| R16 | Integración con CI (GitHub Actions) que falle si la auditoría encuentra problemas críticos |
| R17 | Perfiles preconfigurados para datasets conocidos (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, UGR'16, CTU-13) |

### 6.3 P2 — Futuro (diseñar pensando en ellos)

| ID | Requisito |
|---|---|
| R18 | Monitor de deriva en streaming (Kafka) |
| R19 | Datos de endpoints (EDR) y de phishing (correos, URLs) |
| R20 | Multi-organización con control de acceso |
| R21 | Reportes firmados para auditorías |
| R22 | Versión para telemetría satelital (detección de comandos o telemetría manipulada) |
| R23 | Aprendizaje federado / auditoría sin sacar datos de la red del cliente |

---

## 7. Arquitectura del sistema

### 7.1 Vista general

```
┌──────────────┐    ┌────────────────────────────────────────────────────────────┐
│   FUENTES    │    │                       NÚCLEO VIGÍA                          │
│              │    │                                                            │
│ CSV/Parquet  │──▶ │  ┌───────────┐   ┌──────────────┐   ┌──────────────────┐   │
│ PCAP         │──▶ │  │ Ingesta y │──▶│ Normalizador │──▶│ Perfil de        │   │
│ Zeek logs    │──▶ │  │ lectores  │   │ (esquema     │   │ referencia       │   │
│ Suricata EVE │──▶ │  └───────────┘   │  común)      │   │ (estadísticas,   │   │
│ NetFlow      │──▶ │                  └──────────────┘   │  modelo base)    │   │
└──────────────┘    │                          │          └──────────────────┘   │
                    │         ┌────────────────┼───────────────────┐             │
                    │         ▼                ▼                   ▼             │
                    │  ┌────────────┐  ┌───────────────┐  ┌────────────────┐     │
                    │  │ [1]Auditor │  │[2]Envenena-   │  │[3]Monitor de   │     │
                    │  │  (checks)  │  │   miento      │  │   deriva       │     │
                    │  └─────┬──────┘  └──────┬────────┘  └───────┬────────┘     │
                    │        └────────────────┼───────────────────┘              │
                    │                         ▼                                  │
                    │                ┌─────────────────┐                         │
                    │                │ Motor de        │                         │
                    │                │ hallazgos       │ (severidad, evidencia,  │
                    │                │                 │  recomendación)         │
                    │                └────────┬────────┘                         │
                    └─────────────────────────┼──────────────────────────────────┘
                                              ▼
                     ┌───────────┬────────────┼─────────────┬──────────────┐
                     ▼           ▼            ▼             ▼              ▼
                  Reporte     Reporte       API REST     Panel web     Alertas
                  HTML        JSON                                     (Slack/email/webhook)
```

### 7.2 Principios de diseño

1. **Local primero.** Los datos de seguridad son sensibles. La versión base corre en la máquina o servidor del cliente; nada sale de su red.
2. **Una librería, varias interfaces.** Todo el análisis vive en un paquete Python (`vigia-core`). La CLI, la API y el panel son capas delgadas encima.
3. **Checks como plugins.** Cada verificación es una clase independiente con la misma interfaz. Agregar un check nuevo no toca el resto.
4. **Evidencia siempre.** Cada hallazgo incluye ejemplos concretos, métrica, severidad y cómo corregirlo. Nada de "hay un problema" sin prueba.
5. **Reproducibilidad.** Cada ejecución guarda versión de Vigía, configuración, semilla aleatoria y huella (hash) del dataset.
6. **Escala progresiva.** Empieza en una laptop (millones de filas con Polars/DuckDB); crece a workers y streaming solo cuando haga falta.

### 7.3 Flujo de una auditoría

```
1. Leer archivo ──▶ 2. Detectar formato ──▶ 3. Mapear a esquema común
       │
       ▼
4. Calcular huella (hash) y perfil estadístico
       │
       ▼
5. Ejecutar checks en paralelo (cada uno devuelve 0..N hallazgos)
       │
       ▼
6. Entrenar modelo base (original) ──▶ 7. Aplicar correcciones ──▶ 8. Entrenar modelo base (corregido)
       │
       ▼
9. Unir hallazgos, asignar severidad, generar reporte
```

### 7.4 Interfaz común de un check

```python
class Check(Protocol):
    id: str                 # "leak.temporal"
    name: str               # "Fuga temporal entre entrenamiento y prueba"
    category: str           # "leakage" | "labels" | "duplicates" | "shortcuts" | "validity" | "poisoning" | "drift"
    applies_to: set[str]    # {"flows", "zeek", "tabular"}

    def run(self, ctx: AuditContext) -> list[Finding]: ...

@dataclass
class Finding:
    check_id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    metric: dict[str, float]      # {"duplicate_ratio": 0.11}
    affected_rows: int
    examples: list[dict]          # hasta 10 filas de ejemplo
    recommendation: str
    auto_fix: str | None          # id de la corrección automática, si existe
```

---

## 8. Módulo 1 — Auditor de datasets

Objetivo: encontrar errores accidentales que inflan los resultados. Los checks se agrupan en seis familias.

### 8.1 Validez básica

| Check | Qué busca | Método |
|---|---|---|
| `validity.nan_inf` | Valores NaN o infinitos (CICIDS2017 los tiene en columnas de tasas) | Conteo por columna |
| `validity.constant` | Columnas con un solo valor (no aportan nada) | Cardinalidad = 1 |
| `validity.impossible` | Duraciones negativas, puertos > 65535, protocolos inexistentes, bytes negativos | Reglas del dominio |
| `validity.header_dup` | Filas de encabezado repetidas dentro del archivo (pasa al concatenar CSVs) | Comparación con nombres de columnas |
| `validity.types` | Columnas numéricas guardadas como texto, espacios en nombres de columnas | Inferencia de tipos |
| `validity.schema` | Columnas esperadas que faltan según el perfil del dataset | Validación con Pandera |

### 8.2 Duplicados

| Check | Qué busca | Método |
|---|---|---|
| `dup.exact` | Filas idénticas | Hash por fila (xxhash) |
| `dup.near` | Filas casi idénticas (diferencias mínimas en tiempos) | Redondeo + hash, o MinHash/LSH para escala |
| `dup.cross_split` | Duplicados que aparecen en entrenamiento y en prueba | Intersección de hashes entre splits |
| `dup.class_ratio` | Clases de ataque que son mayoritariamente duplicados (ataques DoS repetitivos) | Porcentaje de duplicados por clase |

### 8.3 Etiquetas

| Check | Qué busca | Método |
|---|---|---|
| `labels.conflict` | Mismas características, distinta etiqueta | Agrupar por hash de características |
| `labels.noise` | Etiquetas probablemente incorrectas | *Confident learning* (librería cleanlab) con probabilidades fuera de muestra (validación cruzada) |
| `labels.window` | Flujos etiquetados como ataque fuera de la ventana de tiempo documentada del ataque, o benignos dentro de ella desde IPs atacantes | Cruce con metadatos del dataset (horarios e IPs de ataque publicados) |
| `labels.imbalance` | Clases con muy pocos ejemplos que hacen poco confiables las métricas | Conteo por clase y advertencia |
| `labels.taxonomy` | Etiquetas inconsistentes ("DoS Hulk", "DoS-Hulk", "dos hulk") | Normalización de texto y agrupamiento |

**Detalle importante:** cleanlab por sí solo no entiende de redes. El valor de Vigía está en combinarlo con reglas del dominio (`labels.window`) y en excluir primero las columnas-atajo; si no, el modelo auxiliar "acierta" gracias al atajo y oculta el ruido.

### 8.4 Fugas (leakage)

| Check | Qué busca | Método |
|---|---|---|
| `leak.temporal` | Datos de prueba anteriores a datos de entrenamiento | Comparar rangos de timestamps entre splits |
| `leak.session` | Flujos de la misma sesión/conexión repartidos entre splits | Agrupar por 5-tupla + ventana de tiempo |
| `leak.host` | Mismo host atacante en entrenamiento y prueba (el modelo memoriza el host) | Agrupar por IP origen/destino |
| `leak.random_split` | El usuario dividió al azar un dataset con dependencia temporal | Heurística + advertencia con referencia a TESSERACT |
| `leak.adversarial` | Entrenamiento y prueba son distinguibles (o sospechosamente idénticos) | *Adversarial validation*: entrenar un clasificador que distinga los splits; AUC ≈ 0.5 esperado para splits aleatorios, AUC alto indica cambio de distribución |

### 8.5 Atajos (shortcuts)

| Check | Qué busca | Método |
|---|---|---|
| `shortcut.single_feature` | Una sola columna predice la etiqueta demasiado bien | Entrenar un árbol poco profundo con cada columna sola; marcar si supera el umbral (ej. 0.95 de accuracy balanceada) |
| `shortcut.identifier` | Columnas identificadoras (IPs, IDs de flujo, timestamps, puertos efímeros) presentes como características | Reglas por nombre + cardinalidad alta + prueba de atajo |
| `shortcut.artifact` | Características que reflejan el laboratorio y no el ataque (TTL fijo de la máquina atacante, tamaño de ventana TCP del sistema operativo del atacante) | Prueba de atajo + lista de características conocidas como artefactos |
| `shortcut.importance` | El modelo base depende de pocas columnas sospechosas | Importancia SHAP del modelo base |

### 8.6 Artefactos del extractor de flujos

| Check | Qué busca | Método |
|---|---|---|
| `flow.termination` | Flujos TCP cortados incorrectamente (por ejemplo, terminar tras un solo FIN o ignorar RST, errores documentados en CICFlowMeter) | Distribución de flags vs. duración; flujos "huérfanos" |
| `flow.zero_payload` | Flujos de ataque sin carga útil que en realidad son restos de conexión | Reglas sobre bytes y paquetes |
| `flow.timeout` | Flujos partidos por timeouts que generan múltiples registros del mismo evento | Agrupamiento por 5-tupla y tiempos contiguos |

### 8.7 Correcciones automáticas

Cada corrección es opcional y queda registrada:

- `fix.drop_duplicates` — eliminar duplicados exactos.
- `fix.drop_identifiers` — quitar columnas-atajo.
- `fix.group_split` — rehacer el split por sesión/host.
- `fix.temporal_split` — rehacer el split respetando el tiempo.
- `fix.relabel_window` — corregir etiquetas usando las ventanas documentadas del ataque.
- `fix.quarantine_noise` — mover etiquetas dudosas a un archivo separado para revisión humana (nunca se borran solas).

### 8.8 Comparación antes/después

Para demostrar el impacto, Vigía entrena el mismo modelo base (LightGBM con parámetros fijos) dos veces:

| Métrica | Dataset original | Dataset corregido |
|---|---|---|
| F1 macro | (ejemplo) 0.99 | (ejemplo) 0.87 |
| Recall por clase | … | … |
| Falsos positivos por cada 10,000 flujos benignos | … | … |

*Los números de esta tabla son ilustrativos; los reales saldrán de los experimentos.*

---

## 9. Módulo 2 — Detector de envenenamiento

Objetivo: encontrar registros insertados a propósito para manipular el modelo.

### 9.1 Tipos de envenenamiento a cubrir

| Tipo | Descripción | Ejemplo en seguridad |
|---|---|---|
| **Cambio de etiqueta (label flipping)** | Registros de ataque etiquetados como benignos | Un atacante con acceso al pipeline de etiquetado marca su tráfico como normal |
| **Inyección de datos** | Registros nuevos fabricados | Tráfico sintético "benigno" muy parecido al del atacante, enviado a una red trampa que alimenta el dataset |
| **Puerta trasera (backdoor/trigger)** | Registros con un patrón específico etiquetados como benignos, para que ese patrón "desactive" la detección | Siempre usar un tamaño de paquete concreto; el modelo aprende que ese tamaño = benigno |
| **Clean-label** | Registros con etiqueta correcta pero diseñados para mover la frontera de decisión | Difícil; se cubre parcialmente en v2 |

### 9.2 Detectores

| Detector | Idea | Implementación |
|---|---|---|
| `poison.loss` | Los registros envenenados suelen tener pérdida alta o comportamiento raro durante el entrenamiento | Registrar pérdida por muestra con validación cruzada; marcar colas extremas |
| `poison.knn` | Un registro "benigno" rodeado de vecinos "ataque" es sospechoso | k vecinos más cercanos (FAISS o scikit-learn) y proporción de etiquetas vecinas |
| `poison.cluster` | Los registros envenenados forman un grupo pequeño y compacto dentro de una clase | Clustering por clase (HDBSCAN) sobre representaciones; grupos pequeños y densos con pocas fuentes → sospecha |
| `poison.spectral` | Firmas espectrales: las muestras con trigger dejan una huella en las representaciones internas | SVD de representaciones por clase; puntaje por proyección en el vector principal (basado en Tran et al., 2018 — verificar referencia) |
| `poison.activation` | Agrupar activaciones de una red neuronal por clase; un grupo separado indica backdoor | Activation clustering (basado en Chen et al., 2018 — verificar referencia) |
| `poison.trigger_search` | Buscar un valor o combinación de valores sobrerrepresentado solo en una parte de la clase benigna | Minería de reglas (frecuencias condicionales) |
| `poison.provenance` | Registros que llegan de una misma fuente, en una ventana corta, con distribución distinta | Metadatos de origen (si el cliente los provee) |

### 9.3 Puntaje combinado

Cada registro recibe un puntaje de sospecha entre 0 y 1 combinando los detectores (promedio ponderado o un meta-modelo entrenado sobre envenenamientos simulados). Se reportan los N más sospechosos, agrupados en "campañas" si comparten características.

### 9.4 Cómo se entrena y evalúa sin datos reales de envenenamiento

No existen muchos datasets públicos con envenenamiento real, así que Vigía incluye un **simulador**:

1. Tomar un dataset limpio (versión corregida).
2. Inyectar envenenamiento controlado: 0.5%, 1%, 5% de etiquetas cambiadas; triggers en una característica; inyecciones sintéticas.
3. Medir precisión y recall de cada detector.
4. Comparar contra líneas base genéricas (Isolation Forest, ECOD de PyOD).

El simulador también es un producto útil por sí mismo: permite a los clientes probar la robustez de sus modelos.

---

## 10. Módulo 3 — Monitor de deriva

Objetivo: avisar cuando el modelo deja de estar al día.

### 10.1 Tipos de deriva

| Tipo | Qué cambia | Ejemplo |
|---|---|---|
| **Deriva de datos (covariate shift)** | La distribución de las características | Nueva aplicación en la red cambia el patrón de puertos |
| **Deriva de concepto** | La relación entre características y etiqueta | Un malware nuevo se comporta como tráfico normal |
| **Deriva de etiquetas (prior shift)** | La proporción de ataques | Campaña masiva de escaneo |
| **Cambio de esquema** | Columnas nuevas, faltantes o con otro tipo | Actualización del sensor |

### 10.2 Métodos

| Método | Uso | Librería |
|---|---|---|
| PSI (Population Stability Index) | Comparar distribuciones por característica | Implementación propia / Evidently |
| Kolmogorov–Smirnov | Características numéricas | SciPy |
| Chi-cuadrado | Características categóricas (protocolo, flags) | SciPy |
| MMD (Maximum Mean Discrepancy) | Deriva multivariada | alibi-detect |
| Clasificador de dominio | Distinguir referencia vs. actual; AUC alto = deriva | scikit-learn / LightGBM |
| ADWIN, DDM, Page-Hinkley | Detectar cambios en streaming | river |
| Confianza del modelo | Caída en la confianza promedio o aumento de predicciones inciertas | Salidas del modelo del cliente |
| Rendimiento con etiquetas tardías | Cuando llegan etiquetas del SOC, medir F1 real en ventana deslizante | Implementación propia |

### 10.3 Lógica de alerta

```
Para cada ventana (ej. cada hora o cada lote):
  1. Calcular métricas de deriva por característica y multivariada
  2. Si deriva > umbral en características importantes (según SHAP) → alerta MEDIA
  3. Si además cae la confianza del modelo → alerta ALTA
  4. Si hay etiquetas y el F1 real cae más de X puntos → alerta CRÍTICA + recomendación de reentrenar
  5. Explicar: top 5 características que cambiaron, con gráficos antes/después
```

### 10.4 Recomendaciones automáticas

- Qué periodo de datos usar para reentrenar.
- Qué muestras nuevas conviene etiquetar primero (aprendizaje activo: las de mayor incertidumbre).
- Si la deriva parece un error del sensor (cambio de esquema) y no un cambio real.

---

## 11. Formatos de entrada y normalización

### 11.1 Formatos soportados

| Formato | Versión | Lector |
|---|---|---|
| CSV / Parquet de flujos (CICFlowMeter, datasets académicos) | MVP | Polars |
| PCAP / PCAPNG | P1 | NFStream (extracción de flujos) o CICFlowMeter corregido; Scapy/dpkt para inspección puntual |
| Zeek (conn.log, dns.log, http.log) | P1 | Parser propio (TSV/JSON) |
| Suricata EVE JSON | P1 | Polars (JSON Lines) |
| NetFlow v5/v9, IPFIX | P2 | nfdump / conversión previa |
| Logs de endpoints (Sysmon, EDR) | P2 | Parser por fuente |

### 11.2 Esquema común (flujos)

Todos los lectores convierten a un esquema interno mínimo, sin perder las columnas originales:

| Campo | Tipo | Descripción |
|---|---|---|
| `ts_start` | timestamp | Inicio del flujo |
| `ts_end` | timestamp | Fin del flujo |
| `src_ip`, `dst_ip` | string | Direcciones (anonimizables) |
| `src_port`, `dst_port` | int | Puertos |
| `proto` | category | Protocolo |
| `duration` | float | Segundos |
| `pkts_fwd`, `pkts_bwd` | int | Paquetes por dirección |
| `bytes_fwd`, `bytes_bwd` | int | Bytes por dirección |
| `label` | category | Etiqueta normalizada |
| `label_raw` | string | Etiqueta original |
| `split` | category | train / test / val / unknown |
| `source_id` | string | Origen del registro (para procedencia) |
| `features.*` | varios | Columnas originales restantes |

### 11.3 Perfiles de datasets conocidos

Archivos YAML con metadatos de cada dataset público: nombres de columnas, IPs atacantes y víctimas documentadas, horarios de cada ataque, errores conocidos. Ejemplo:

```yaml
id: cic-ids-2017
reader: cicflowmeter_csv
column_aliases:
  " Destination Port": dst_port
  " Label": label_raw
known_attackers: ["205.174.165.69", "205.174.165.70", "205.174.165.71"]  # según la página oficial de CIC-IDS2017; verificar
attack_windows:
  - label: "DoS Hulk"
    day: "2017-07-05"
    start: "..."                           # completar con la documentación oficial
    end: "..."
known_issues:
  - "flow.termination"
  - "validity.nan_inf"
```

*Los valores concretos deben tomarse de la documentación oficial del dataset; los de arriba son marcadores.*

---

## 12. Selección de tecnologías

Criterios: gratis o de código abierto, conocido por la comunidad de datos, corre en una laptop, escala después, y usa lo que ya sabes (Python y SQL).

### 12.1 Núcleo de datos

| Necesidad | Elección | Por qué | Alternativas |
|---|---|---|---|
| Lenguaje | **Python 3.12** | Ecosistema de ML y seguridad; ya lo sabes | — |
| DataFrames | **Polars** | Mucho más rápido y eficiente en memoria que pandas para millones de filas; API expresiva | pandas (compatibilidad) |
| Consultas SQL sobre archivos | **DuckDB** | SQL directo sobre Parquet/CSV sin servidor; ideal para agrupamientos y cruces entre splits | SQLite |
| Formato en disco | **Apache Parquet (PyArrow)** | Columnar, comprimido, estándar | Feather |
| Validación de esquema | **Pandera** | Esquemas declarativos para DataFrames, compatible con Polars | Great Expectations (más pesado) |
| Hashing rápido | **xxhash** | Hash de filas para duplicados | hashlib |
| Casi-duplicados a escala | **datasketch (MinHash/LSH)** | Evita comparar todas las parejas | FAISS |

### 12.2 Machine learning

| Necesidad | Elección | Por qué |
|---|---|---|
| Modelos base | **LightGBM** + **scikit-learn** | Rápidos en datos tabulares, buenos resultados sin GPU |
| Ruido en etiquetas | **cleanlab** | Implementación madura de *confident learning* |
| Detección de anomalías | **PyOD** (Isolation Forest, ECOD, etc.) | Muchos algoritmos con la misma interfaz; líneas base |
| Vecinos cercanos a escala | **FAISS** (CPU) | Búsqueda k-NN en millones de vectores |
| Clustering | **HDBSCAN** (en scikit-learn) | Encuentra grupos pequeños y densos sin fijar k |
| Explicabilidad | **SHAP** | Importancia de características para atajos y deriva |
| Deriva por lotes | **Evidently** y/o **alibi-detect** | Pruebas estadísticas listas y reportes |
| Deriva en streaming | **river** | ADWIN, DDM, Page-Hinkley |
| Redes neuronales (fase 2, detectores basados en activaciones) | **PyTorch** | Estándar en investigación |
| Seguimiento de experimentos | **MLflow** | Registrar métricas del benchmark interno |

### 12.3 Datos de red

| Necesidad | Elección | Por qué |
|---|---|---|
| PCAP → flujos | **NFStream** | Extracción de flujos en Python, rápida |
| Compatibilidad con datasets CIC | **CICFlowMeter (versión corregida por Engelen)** | Reproducir las características de los datasets académicos |
| Inspección de paquetes | **Scapy**, **dpkt** | Validaciones puntuales |
| Logs | **Zeek**, **Suricata** (como fuentes) | Estándares en la industria |
| Anonimización de IPs | **Crypto-PAn** (preserva prefijos) | Permite compartir datos sin exponer IPs reales |

### 12.4 Aplicación

| Capa | Elección | Por qué |
|---|---|---|
| CLI | **Typer** + **Rich** | CLI moderna con salida legible |
| API | **FastAPI** | Rápida, tipada, documentación automática |
| Tareas en segundo plano | **Arq** o **Celery** + **Redis** | Auditorías largas sin bloquear la API (Arq es más simple para empezar) |
| Base de datos de la app | **PostgreSQL** | Metadatos, hallazgos, usuarios |
| Series de tiempo (deriva) | **TimescaleDB** (extensión de PostgreSQL) | Métricas por ventana sin otra base de datos |
| Almacenamiento de archivos | **MinIO** (compatible con S3) | Datasets y reportes; en la nube, S3 directamente |
| Streaming (P2) | **Apache Kafka** o **Redpanda** | Monitor en tiempo real |
| Panel web (MVP) | **Streamlit** | Rápido de construir en Python |
| Panel web (producto) | **Next.js** + **TypeScript** + **Plotly/ECharts** | Experiencia profesional cuando haya clientes |
| Reportes | **Jinja2** + **Plotly** → HTML autocontenido; **WeasyPrint** para PDF | Reportes compartibles |
| Autenticación (P2) | **Keycloak** o proveedor OIDC | Multi-organización |

### 12.5 Ingeniería

| Necesidad | Elección |
|---|---|
| Gestión de dependencias | **uv** (o Poetry) |
| Calidad de código | **Ruff** (lint + formato), **mypy** (tipos) |
| Pruebas | **pytest**, **Hypothesis** (pruebas basadas en propiedades) |
| Contenedores | **Docker** + **Docker Compose** |
| CI/CD | **GitHub Actions** |
| Documentación | **MkDocs Material** |
| Versionado de datos | **DVC** (opcional) |
| Seguridad de dependencias | **pip-audit**, **Dependabot** |
| Licencia del núcleo | **Apache 2.0** (permite uso comercial y atrae contribuciones) |

### 12.6 Infraestructura y costo

- **Fase 1–2:** todo corre en tu laptop o en una máquina virtual pequeña. Costo cercano a cero.
- **Fase 3:** un servidor en la nube para la demo pública y el panel. Aprovechar créditos para estudiantes y startups (GitHub Student Developer Pack, programas de créditos de proveedores de nube; verificar condiciones vigentes).
- **Clientes empresariales:** se despliega en su infraestructura (Docker/Kubernetes), así que el costo de cómputo lo asume el cliente.

### 12.7 Decisiones y compromisos

| Decisión | Ganamos | Perdemos | Revisar cuando… |
|---|---|---|---|
| Polars en vez de Spark | Simplicidad, velocidad en una máquina | Límite de memoria de un solo nodo | Un cliente tenga datasets > 500 GB |
| Local primero | Confianza del cliente, privacidad | Menos datos agregados para mejorar el producto | Haya clientes que prefieran SaaS |
| Streamlit en MVP | Velocidad de desarrollo | Apariencia y control limitados | Haya clientes pagando |
| Arq en vez de Celery | Menos complejidad | Menos funciones | Se necesiten flujos de tareas complejos |

---

## 13. Modelo de datos (aplicación)

```sql
-- Organizaciones y usuarios (P2)
CREATE TABLE organizations (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Datasets registrados
CREATE TABLE datasets (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id),
  name TEXT NOT NULL,
  profile_id TEXT,              -- ej. 'cic-ids-2017' o NULL
  storage_uri TEXT NOT NULL,    -- s3://... o ruta local
  sha256 TEXT NOT NULL,         -- huella del contenido
  n_rows BIGINT,
  n_cols INT,
  schema_json JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Ejecuciones (auditoría, escaneo de envenenamiento, deriva)
CREATE TABLE runs (
  id UUID PRIMARY KEY,
  dataset_id UUID REFERENCES datasets(id),
  kind TEXT CHECK (kind IN ('audit','poison','drift')),
  status TEXT CHECK (status IN ('queued','running','done','failed')),
  vigia_version TEXT,
  config_json JSONB,
  seed INT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);

-- Hallazgos
CREATE TABLE findings (
  id UUID PRIMARY KEY,
  run_id UUID REFERENCES runs(id),
  check_id TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT CHECK (severity IN ('critical','high','medium','low','info')),
  title TEXT,
  description TEXT,
  metric_json JSONB,
  affected_rows BIGINT,
  examples_json JSONB,
  recommendation TEXT,
  auto_fix TEXT
);

-- Puntajes por registro (envenenamiento / etiquetas dudosas)
CREATE TABLE row_scores (
  run_id UUID REFERENCES runs(id),
  row_key TEXT,                 -- hash o índice del registro
  score REAL,
  detectors_json JSONB,
  PRIMARY KEY (run_id, row_key)
);

-- Métricas de deriva por ventana (hypertable de TimescaleDB)
CREATE TABLE drift_metrics (
  monitor_id UUID,
  window_start TIMESTAMPTZ NOT NULL,
  feature TEXT,
  method TEXT,                  -- 'psi','ks','mmd','domain_auc'
  value REAL,
  threshold REAL,
  alert_level TEXT
);
-- SELECT create_hypertable('drift_metrics', 'window_start');

-- Monitores configurados
CREATE TABLE monitors (
  id UUID PRIMARY KEY,
  reference_dataset_id UUID REFERENCES datasets(id),
  name TEXT,
  window TEXT,                  -- '1 hour', '1 day'
  config_json JSONB,
  notify_json JSONB             -- webhooks, correo, Slack
);
```

---

## 14. API y CLI

### 14.1 CLI

```bash
# Instalar
pip install vigia

# Auditar un dataset (con split ya definido en una columna)
vigia audit data/flows.parquet --label-col Label --split-col split --report out/

# Auditar usando un perfil conocido
vigia audit data/cicids2017/ --profile cic-ids-2017 --report out/

# Aplicar correcciones seguras y guardar el dataset limpio
vigia fix data/flows.parquet --apply drop_duplicates,drop_identifiers,group_split -o data/flows_clean.parquet

# Comparar rendimiento antes/después
vigia compare data/flows.parquet data/flows_clean.parquet --model lightgbm

# Buscar envenenamiento
vigia poison-scan data/train.parquet --label-col label --top 500

# Simular envenenamiento para probar robustez
vigia poison-sim data/train_clean.parquet --type label_flip --rate 0.01 -o data/train_poisoned.parquet

# Crear referencia y revisar deriva de un lote nuevo
vigia drift reference data/train_clean.parquet --name prod-nids
vigia drift check data/week_38.parquet --reference prod-nids

# Usar en CI: falla si hay hallazgos críticos
vigia audit data/train.parquet --fail-on critical
```

### 14.2 API REST (FastAPI)

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/datasets` | Registrar un dataset (subida o URI) |
| GET | `/datasets/{id}` | Metadatos y esquema |
| POST | `/datasets/{id}/audits` | Lanzar auditoría (devuelve `run_id`) |
| POST | `/datasets/{id}/poison-scans` | Lanzar escaneo de envenenamiento |
| GET | `/runs/{id}` | Estado de una ejecución |
| GET | `/runs/{id}/findings` | Hallazgos (filtros: severidad, categoría) |
| GET | `/runs/{id}/report?format=html\|json\|pdf` | Descargar reporte |
| GET | `/runs/{id}/row-scores?top=100` | Registros más sospechosos |
| POST | `/monitors` | Crear monitor de deriva |
| POST | `/monitors/{id}/batches` | Enviar un lote de datos nuevos |
| GET | `/monitors/{id}/metrics?from=&to=` | Métricas de deriva |
| GET | `/checks` | Lista de checks disponibles y su descripción |

Ejemplo de respuesta de un hallazgo:

```json
{
  "check_id": "shortcut.single_feature",
  "severity": "critical",
  "title": "La columna 'Source IP' predice la etiqueta casi perfectamente",
  "metric": {"balanced_accuracy": 0.981, "threshold": 0.95},
  "affected_rows": 2830743,
  "recommendation": "Eliminar 'Source IP' de las características o dividir por host.",
  "auto_fix": "drop_identifiers"
}
```

### 14.3 SDK en Python

```python
import vigia

ds = vigia.load("data/flows.parquet", label_col="Label", profile="cic-ids-2017")
report = vigia.audit(ds, checks="all", seed=42)

print(report.summary())            # conteo por severidad
report.to_html("out/report.html")

clean = vigia.fix(ds, report, apply=["drop_duplicates", "drop_identifiers", "group_split"])
cmp = vigia.compare(ds, clean, model="lightgbm")
print(cmp.table())
```

---

## 15. Reportes y experiencia de usuario

### 15.1 Estructura del reporte de auditoría

1. **Semáforo general:** verde / amarillo / rojo, con el conteo de hallazgos por severidad.
2. **Resumen en tres frases** en lenguaje simple (qué está mal y qué tan grave es).
3. **Impacto en el modelo:** tabla antes/después (sección 8.8).
4. **Hallazgos ordenados por severidad:** cada uno con métrica, ejemplos, gráfico y recomendación.
5. **Perfil del dataset:** filas, columnas, clases, rango de fechas, distribución por día.
6. **Anexo técnico:** configuración, versión, semilla, hash del dataset (para reproducibilidad).

### 15.2 Niveles de severidad

| Severidad | Significado | Ejemplo |
|---|---|---|
| Crítica | Las métricas reportadas probablemente no son válidas | Atajo por IP; duplicados cruzando splits |
| Alta | Distorsión importante de resultados | 10% de etiquetas dudosas en una clase |
| Media | Afecta clases o escenarios concretos | Clase con menos de 50 ejemplos |
| Baja | Higiene de datos | Nombres de columnas con espacios |
| Info | Dato útil, no un problema | Distribución de protocolos |

### 15.3 Panel web (P1)

- **Inicio:** datasets registrados y su último semáforo.
- **Detalle de auditoría:** filtros por severidad/categoría, ejemplos, botón "aplicar corrección".
- **Revisión humana:** cola de registros sospechosos (etiquetas dudosas, posibles envenenados) para que un analista confirme o descarte; esas decisiones mejoran los detectores.
- **Monitores:** gráficos de deriva por característica y alertas.

---

## 16. Cómo validar que funciona

### 16.1 Datasets de prueba

| Dataset | Uso |
|---|---|
| CIC-IDS2017 (original y versión corregida de Engelen et al.) | Validación principal: ¿Vigía detecta los errores que ya se documentaron? |
| CSE-CIC-IDS2018 (y versión refinada de Liu et al.) | Segunda validación |
| UNSW-NB15 | Dataset de otro laboratorio y otro extractor |
| UGR'16 | Tráfico real con contaminación documentada (envenenamiento/etiquetado) |
| CTU-13 | Botnets, útil para fugas por host |
| OPS-SAT / ESA-ADB (P2) | Prueba de generalización a telemetría satelital |

*Revisar las licencias y condiciones de uso de cada dataset antes de redistribuir resultados.*

### 16.2 Experimentos

1. **Recuperar errores conocidos.** Comparar el dataset original con el corregido y contar cuántas diferencias detecta Vigía sin ayuda. Métrica: recall de errores conocidos.
2. **Errores sembrados.** Inyectar duplicados, etiquetas cambiadas y fugas en un dataset limpio, en proporciones conocidas. Métricas: precisión y recall por check.
3. **Impacto real.** Entrenar el modelo base con el dataset original y el corregido, y evaluar en un dataset distinto (entrenar en 2017, probar en 2018). Si la corrección mejora la generalización entre datasets, es una prueba fuerte de valor.
4. **Envenenamiento.** Usar el simulador (sección 9.4) con distintas tasas y tipos. Comparar contra Isolation Forest y ECOD.
5. **Deriva.** Usar la separación temporal natural (días distintos de CIC-IDS2017, o 2017 → 2018) y medir con cuánta anticipación Vigía alerta antes de que caiga el F1.
6. **Falsas alarmas.** Correr Vigía sobre datasets limpios y sintéticos sin errores; debe reportar pocos hallazgos graves.

### 16.3 Criterios para decir "funciona"

- Recall ≥ 80% sobre errores conocidos de CIC-IDS2017 (objetivo 1).
- Detectores de envenenamiento con mejor F1 que las líneas base genéricas en al menos 3 de 4 escenarios.
- Menos de 1 hallazgo crítico falso por dataset limpio de prueba.
- Resultados publicados de forma reproducible (repositorio + notebook).

---

## 17. Seguridad y privacidad de la propia herramienta

Una herramienta que toca datos de seguridad tiene que ser segura.

- **Procesamiento local por defecto;** no hay telemetría sin permiso explícito.
- **Anonimización opcional** de IPs con Crypto-PAn antes de cualquier análisis compartido.
- **Cifrado** en reposo (MinIO/S3 con cifrado del lado del servidor) y en tránsito (TLS).
- **Reportes sin datos sensibles** por defecto: los ejemplos muestran IPs anonimizadas.
- **Control de acceso** por organización y rol (P2).
- **Registro de auditoría** de quién ejecutó qué y cuándo.
- **Cadena de suministro:** dependencias fijadas, `pip-audit` en CI, imágenes Docker mínimas y firmadas.
- **Lectura segura de archivos:** nunca usar `pickle` con archivos de usuarios; límites de tamaño; PCAPs procesados en un contenedor aislado.
- **Uso responsable:** el simulador de envenenamiento es para pruebas de robustez sobre datos propios; documentarlo así.

---

## 18. Estructura del repositorio

```
vigia/
├── README.md
├── LICENSE                       # Apache 2.0
├── pyproject.toml
├── docker-compose.yml
├── docs/                         # MkDocs
│   ├── index.md
│   ├── checks/                   # una página por check
│   └── benchmarks.md
├── src/vigia/
│   ├── __init__.py
│   ├── cli.py                    # Typer
│   ├── core/
│   │   ├── context.py            # AuditContext
│   │   ├── findings.py           # Finding, severidades
│   │   ├── registry.py           # registro de checks
│   │   └── hashing.py
│   ├── io/
│   │   ├── readers/              # csv, parquet, zeek, suricata, pcap
│   │   ├── schema.py             # esquema común
│   │   └── anonymize.py          # Crypto-PAn
│   ├── profiles/                 # YAML de datasets conocidos
│   ├── checks/
│   │   ├── validity.py
│   │   ├── duplicates.py
│   │   ├── labels.py
│   │   ├── leakage.py
│   │   ├── shortcuts.py
│   │   └── flows.py
│   ├── fixes/
│   ├── poison/
│   │   ├── detectors/            # loss, knn, cluster, spectral, activation, trigger
│   │   ├── scoring.py
│   │   └── simulator.py
│   ├── drift/
│   │   ├── batch.py
│   │   ├── streaming.py
│   │   └── alerts.py
│   ├── models/                   # modelos base para diagnóstico
│   ├── compare.py
│   └── report/
│       ├── templates/            # Jinja2
│       └── render.py
├── api/                          # FastAPI (P1)
├── dashboard/                    # Streamlit (MVP) / Next.js (producto)
├── benchmarks/                   # scripts reproducibles de la sección 16
├── notebooks/
└── tests/
    ├── unit/
    ├── property/                 # Hypothesis
    └── fixtures/                 # datasets diminutos con errores sembrados
```

---

## 19. Plan de trabajo por fases

Supuesto: 1–2 personas, a tiempo parcial (estudiante). Ajustar según la carga de la universidad.

### Fase 0 — Validación rápida (semanas 1–2)
- Descargar CIC-IDS2017 original y la versión corregida de Engelen et al.
- Probar cleanlab y Deepchecks sobre CIC-IDS2017 y anotar qué errores conocidos **no** detectan (esta lista define la diferenciación).
- Entrenar LightGBM con ambos datasets y documentar la diferencia de métricas.
- Implementar a mano 5 checks: duplicados, NaN/inf, atajo por columna, fuga temporal, fuga por host.
- **Entregable:** notebook + publicación corta (blog técnico o hilo) con los resultados.

### Fase 1 — MVP del auditor (semanas 3–10)
- Estructura del paquete, interfaz de checks, registro y hallazgos.
- Todos los requisitos P0 (R1–R10).
- Perfil YAML para CIC-IDS2017 y CSE-CIC-IDS2018.
- Reporte HTML y JSON.
- Pruebas con datasets diminutos con errores sembrados.
- Publicar en GitHub y PyPI.
- **Entregable:** `pip install vigia` funcional + benchmark de la sección 16.2 (experimentos 1–3).

### Fase 2 — Envenenamiento y deriva por lotes (semanas 11–20)
- Simulador de envenenamiento.
- Detectores `loss`, `knn`, `cluster`, `trigger_search`.
- Monitor de deriva por lotes (PSI, KS, chi-cuadrado, clasificador de dominio).
- Lectores de Zeek y Suricata; PCAP con NFStream.
- Integración con GitHub Actions.
- **Entregable:** versión 0.5 + artículo técnico o preprint (arXiv) con los resultados del benchmark.

### Fase 3 — Plataforma (semanas 21–32)
- API FastAPI, workers, PostgreSQL/TimescaleDB, MinIO.
- Panel Streamlit con cola de revisión humana.
- Alertas (webhook, correo, Slack).
- Detectores basados en representaciones (spectral, activation) con PyTorch.
- Primeros pilotos con 2–3 organizaciones.
- **Entregable:** versión 1.0 desplegable con Docker Compose.

### Fase 4 — Producto comercial (después del mes 8)
- Monitor en streaming (Kafka/Redpanda).
- Multi-organización, SSO, reportes firmados.
- Panel en Next.js.
- Nuevos dominios: logs de endpoints, phishing, telemetría satelital.

### Hitos de decisión

| Momento | Pregunta | Si la respuesta es "no"… |
|---|---|---|
| Fin de Fase 0 | ¿Las herramientas genéricas dejan pasar errores importantes? | Replantear la diferenciación o pivotar |
| Fin de Fase 1 | ¿Hay usuarios usando el paquete (estrellas, issues, descargas)? | Mejorar la comunicación o el enfoque del problema |
| Mitad de Fase 3 | ¿Algún piloto está dispuesto a pagar o firmar una carta de intención? | Considerar la vía académica/open source o buscar otro segmento |

---

## 20. Modelo de negocio

### 20.1 Estrategia: open-core

- **Núcleo abierto (Apache 2.0):** CLI, checks del auditor, perfiles de datasets públicos, reportes. Atrae investigadores y estudiantes, genera confianza y reputación.
- **Versión comercial:** plataforma con panel, monitor de deriva continuo, detectores avanzados de envenenamiento, cola de revisión humana, multi-organización, reportes firmados, soporte.

### 20.2 Quién pagaría

| Segmento | Qué compra | Por qué pagaría |
|---|---|---|
| Empresas que venden productos de seguridad con ML | Licencia de la plataforma | Evitar lanzar modelos con métricas infladas; proteger su pipeline de datos |
| Equipos de SOC grandes con modelos propios | Monitor de deriva | Saber cuándo reentrenar |
| Consultoras y auditoras de IA | Reportes firmados | Evaluar modelos de terceros |
| Proveedores de datos de amenazas | Certificación de calidad de sus datasets | Diferenciarse |
| Universidades y centros de investigación | Soporte o plan académico | Usualmente pagan poco; valor principal: reputación y citas |

**Precios:** no se definen aquí. Cualquier cifra debe salir de conversaciones con los pilotos. Formas posibles (estimación, no validada): suscripción anual por organización, por volumen de datos monitoreado, o por proyecto de auditoría.

### 20.3 Canales

- Publicaciones técnicas con resultados reproducibles (el mejor marketing en este nicho).
- Presentaciones en conferencias y comunidades (BSides, meetups de ML y seguridad, grupos universitarios).
- Contacto directo con autores de papers sobre calidad de datasets.
- Integraciones visibles: GitHub Action, conectores con plataformas de MLOps.

### 20.4 Ventaja desde El Salvador

- Costos bajos para iterar.
- Producto de software que se vende de forma remota.
- Posible acceso a programas de apoyo a startups de la región y a competencias universitarias (investigar opciones vigentes).

---

## 21. Competencia y diferenciación

| Tipo | Ejemplos | Qué cubren | Qué no cubren |
|---|---|---|---|
| Calidad de datos genérica | cleanlab, Deepchecks, Great Expectations, tabaudit | Etiquetas dudosas, duplicados, validaciones de esquema, fugas genéricas | Semántica de redes (sesiones, hosts, extractores de flujos, ventanas de ataque) |
| Monitoreo de modelos (MLOps) | Evidently y plataformas comerciales de observabilidad de ML | Deriva genérica | Contexto de seguridad, envenenamiento |
| Correcciones académicas | Versiones corregidas de CIC-IDS2017/2018 | Un dataset concreto | Herramienta reutilizable |
| Metodologías de papers | Detección de contaminación en UGR'16, etc. | Métodos específicos | Producto instalable |
| Seguridad de IA (adversarial ML) | Librerías de ataques y defensas (por ejemplo, Adversarial Robustness Toolbox de IBM) | Ataques y defensas generales, incluido envenenamiento | Flujo integrado para datasets de seguridad de red |

**Diferenciación de Vigía:**

1. Entiende el dominio: sesiones, hosts, extractores de flujos, ventanas de ataque, artefactos de laboratorio.
2. Cubre las tres etapas (antes, durante, después) con el mismo núcleo.
3. Trae perfiles listos para los datasets más usados.
4. Demuestra el impacto con la comparación antes/después.

*Nota: la búsqueda de competidores fue limitada. Antes de invertir en la Fase 3, hacer un análisis de competencia más profundo.*

---

## 22. Riesgos y mitigaciones

| Riesgo | Probabilidad | Impacto | Mitigación |
|---|---|---|---|
| Las herramientas genéricas ya detectan casi todo | Media | Alto | Fase 0 lo verifica antes de invertir; enfocarse en checks del dominio |
| Los académicos usan la herramienta pero nadie paga | Alta | Alto | Open-core; buscar pilotos empresariales desde la Fase 2 |
| Falsos positivos que generan desconfianza | Media | Alto | Benchmark público, umbrales configurables, revisión humana |
| Empresas no comparten datos | Alta | Medio | Despliegue local; anonimización |
| Detectores de envenenamiento poco efectivos en datos tabulares | Media | Medio | Empezar con detectores simples y medir; publicar resultados honestos |
| Un competidor grande agrega la función | Media | Alto | Moverse rápido en el nicho; comunidad y reputación |
| Carga académica limita el avance | Alta | Medio | Plan por fases con entregables pequeños; posible uso como tesis o proyecto de curso |
| Uso malicioso del simulador | Baja | Medio | Documentación de uso responsable; el simulador solo opera sobre datos propios |

---

## 23. Métricas de éxito

### Indicadores tempranos (semanas)
- Tiempo desde la instalación hasta el primer reporte: < 10 minutos.
- Porcentaje de ejecuciones que terminan sin error: > 95%.
- Estrellas, forks e issues en GitHub; descargas en PyPI.

### Indicadores de producto (meses)
- Recall sobre errores conocidos (objetivo ≥ 80%).
- Tasa de hallazgos aceptados por usuarios en la cola de revisión.
- Número de organizaciones en piloto.
- Citas o menciones en papers.

### Indicadores de negocio (largo plazo)
- Cartas de intención o contratos firmados.
- Retención de clientes.
- Ingresos recurrentes.

---

## 24. Habilidades a desarrollar

| Área | Qué aprender | Recursos sugeridos |
|---|---|---|
| Redes | TCP/IP, flujos, NetFlow, Zeek, Suricata | Documentación oficial de Zeek y Suricata; laboratorios con Wireshark |
| ML tabular | Validación cruzada, LightGBM, métricas desbalanceadas | Documentación de scikit-learn y LightGBM |
| Calidad de datos | Confident learning, adversarial validation, fugas | Documentación de cleanlab; paper de Arp et al. |
| Seguridad de ML | Envenenamiento, backdoors, defensas | Surveys de adversarial ML; Adversarial Robustness Toolbox |
| Deriva | PSI, KS, MMD, ADWIN | Documentación de Evidently, alibi-detect, river |
| Ingeniería | Empaquetado, pruebas, Docker, CI | Guías de Python Packaging; documentación de GitHub Actions |
| Producto | Entrevistas con usuarios, pilotos | Conversaciones con equipos de seguridad y autores de papers |

---

## 25. Primeros pasos concretos (esta semana)

1. Crear el repositorio `vigia` con licencia Apache 2.0 y la estructura de la sección 18.
2. Descargar CIC-IDS2017 (CSV de MachineLearningCSV) desde la página oficial del Canadian Institute for Cybersecurity.
3. Descargar la versión corregida desde la página de Engelen et al. (DistriNet, KU Leuven).
4. En un notebook:
   - cargar ambos con Polars;
   - contar duplicados, NaN e infinitos;
   - entrenar LightGBM con cada una y comparar F1;
   - entrenar un árbol con cada columna sola para encontrar atajos.
5. Probar cleanlab sobre el dataset original y anotar qué detecta y qué no.
6. Escribir un resumen de una página con los resultados.
7. Contactar con ese resumen a los autores de los papers (Engelen; Arp y Rieck) para pedir retroalimentación.

---

## 26. Preguntas abiertas

| Pregunta | Quién responde | ¿Bloquea? |
|---|---|---|
| ¿Qué errores de CIC-IDS2017 no detectan las herramientas genéricas? | Ingeniería (Fase 0) | Sí |
| ¿Qué tan efectivos son los detectores de envenenamiento en datos de flujos? | Investigación (Fase 2) | No |
| ¿Qué formato de datos usan realmente los equipos de seguridad que entrenan modelos? | Entrevistas con usuarios | Sí, antes de Fase 3 |
| ¿Qué licencias tienen los datasets públicos para redistribuir versiones corregidas? | Legal / revisión de licencias | No (solo para publicar datasets) |
| ¿Quién paga primero: empresas de producto o SOCs? | Pilotos | Sí, antes de Fase 4 |
| ¿Es viable la extensión a telemetría satelital con el CubeSat de la universidad? | Equipo del CubeSat | No |

---

## 27. Referencias

- Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., Rieck, K. (2022). *Dos and Don'ts of Machine Learning in Computer Security.* 31st USENIX Security Symposium, pp. 3971–3988. https://www.usenix.org/conference/usenixsecurity22/presentation/arp
- Engelen, G., Rimmer, V., Joosen, W. (2021). *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study.* IEEE Security and Privacy Workshops (SPW), pp. 7–12. doi:10.1109/SPW53761.2021.00009. https://intrusion-detection.distrinet-research.be/WTMC2021/index.html
- Liu, L., Engelen, G., Lynar, T., Essam, D., Joosen, W. (2022). *Error Prevalence in NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018.* IEEE Conference on Communications and Network Security (CNS).
- Lanvin, M. et al. (2023). *Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes.* Risks and Security of Internet and Systems (CRiSIS). https://link.springer.com/chapter/10.1007/978-3-031-31108-6_2
- Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., Cavallaro, L. (2019). *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time.* USENIX Security Symposium.
- Sharafaldin, I., Lashkari, A. H., Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP. (Paper original de CIC-IDS2017.) Página del dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- DeGrave, A. J., Janizek, J. D., Lee, S.-I. (2021). *AI for radiographic COVID-19 detection selects shortcuts over signal.* Nature Machine Intelligence, 3, 610–619. https://www.nature.com/articles/s42256-021-00338-7
- Estudio sobre detección de datasets de entrenamiento contaminados para NIDS (caso UGR'16), publicado en acceso abierto (2024). https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10819357/
- *Faulty use of the CIC-IDS 2017 dataset in information security research* (2023). Journal of Computer Virology and Hacking Techniques. https://link.springer.com/article/10.1007/s11416-023-00509-7
- Tran, B., Li, J., Madry, A. (2018). *Spectral Signatures in Backdoor Attacks.* NeurIPS. (Verificar detalles antes de citar formalmente.)
- Chen, B. et al. (2018). *Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering.* arXiv. (Verificar detalles antes de citar formalmente.)
- Northcutt, C., Jiang, L., Chuang, I. (2021). *Confident Learning: Estimating Uncertainty in Dataset Labels.* Journal of Artificial Intelligence Research. (Base de cleanlab; verificar detalles.)
- tabaudit (proyecto de código abierto para auditar datasets tabulares). https://github.com/sadiasamia121912/tabaudit

**Nota sobre la evidencia:** las referencias con enlace fueron consultadas al preparar este documento. Las marcadas con "verificar" son trabajos conocidos cuyos detalles bibliográficos deben confirmarse antes de citarlos en un paper o presentación. La cifra de 6.67% / 7.53% de etiquetas corruptas se tomó de una cita secundaria (Cantone et al.); conviene leer el trabajo original.

---

## 28. Glosario

- **Adversarial validation:** entrenar un modelo para distinguir dos conjuntos de datos; si lo logra fácilmente, los conjuntos son distintos.
- **Atajo (shortcut):** característica que permite al modelo acertar sin aprender el fenómeno real (por ejemplo, la IP del atacante del laboratorio).
- **Backdoor / trigger:** patrón oculto que hace que el modelo se comporte de forma incorrecta cuando aparece.
- **CICFlowMeter:** herramienta que convierte capturas de paquetes en flujos con estadísticas; usada para crear CIC-IDS2017.
- **Confident learning:** método para estimar qué etiquetas son probablemente incorrectas usando las probabilidades de un modelo.
- **Data snooping:** usar información del conjunto de prueba (directa o indirectamente) durante el desarrollo del modelo.
- **Deriva (drift):** cambio en los datos o en su relación con las etiquetas a lo largo del tiempo.
- **Envenenamiento (poisoning):** manipulación intencional de los datos de entrenamiento.
- **Flujo (flow):** resumen de una conversación de red (misma 5-tupla: IP y puerto de origen y destino, y protocolo) durante un periodo.
- **Fuga (leakage):** información que no estaría disponible en la vida real pero que el modelo usa durante la evaluación.
- **NIDS:** sistema de detección de intrusiones en red.
- **PSI:** índice de estabilidad poblacional; mide cuánto cambió una distribución.
- **SHAP:** método para explicar cuánto aporta cada característica a una predicción.
- **SOC:** centro de operaciones de seguridad.
- **Split:** división de los datos en entrenamiento, validación y prueba.
