# Cómo reproducir los resultados

Cómo volver a correr los benchmarks de [`benchmarks/RESULTADOS.md`](../benchmarks/RESULTADOS.md).
Si una cifra no te da, o encontrás un hallazgo que no se sostiene, abrí un issue
con la plantilla "hallazgo equivocado": es la contribución más útil.

## Entorno

```bash
git clone https://github.com/Joshua203-byte/vigia-nids
cd vigia-nids/vigia
pip install -e ".[dev,ml,parquet,api]"
```

Las cifras de CIC-IDS2017 de RESULTADOS se midieron con Python 3.13,
LightGBM 4.7.0 y Polars 1.44.2. Otras versiones de LightGBM pueden mover A y B
(ver "Por qué cambiaron A y B" en RESULTADOS).

**Recursos.** Los experimentos sobre CIC-IDS2017 completo (3,1 M de filas)
llegaron a ~11 GB de RAM. Con 10 semillas, A y B tardan entre 4 y 10 minutos
por semilla en una máquina de 28 hilos.

## Los datos

Los datasets **no están en el repositorio** y no se redistribuyen: cada uno se
descarga de su fuente y se deja en una carpeta local ignorada por git
(`data/`, `Datadeprueba/`).

| Dataset | De dónde | Qué se usó |
|---|---|---|
| NSL-KDD | `python benchmarks/fetch_datasets.py nsl-kdd` | Lo baja el script |
| CIC-IDS2017 original | [UNB](https://www.unb.ca/cic/datasets/ids-2017.html), por formulario | `GeneratedLabelledFlows.zip` (carpeta `TrafficLabelling`, 8 CSV, 3.119.345 filas) para A, B, C y los checks de fuga; `MachineLearningCSV.zip` para la variante sin IPs |
| CIC-IDS2017 corregido | [Kaggle, `dhoogla/distrinetcicids2017`](https://www.kaggle.com/datasets/dhoogla/distrinetcicids2017) (parquet) | 1.787.358 filas × 84 columnas |
| CSE-CIC-IDS2018 | bucket público del dataset, "Processed Traffic Data for ML Algorithms" | 10 CSV |
| UNSW-NB15 | [sitio de los autores](https://research.unsw.edu.au/projects/unsw-nb15-dataset), carpeta "CSV Files" | training-set, testing-set y 4 CSV crudos |
| CTU-13 | los 13 escenarios `.binetflow` oficiales | 4,9 GB |
| UGR'16 | no hay fuente de flujos accesible | solo una muestra de 5.000 filas |

**Una salvedad sobre el corregido.** La versión que se usó viene de la copia de
Kaggle, que se presenta como derivada del trabajo de Engelen, Rimmer y Joosen
(IEEE SPW 2021). No se verificó que sea idéntica a la que publican los autores;
si no lo es, "cero duplicados" podría deberse en parte a que esa copia ya viene
deduplicada. Cualquier discrepancia que encuentres ahí es de interés.

## Estructura de carpetas esperada

```
Datadeprueba/
├── Dataoriginal/
│   ├── GeneratedLabelledFlows/TrafficLabelling/   # 8 CSV
│   └── MachineLearningCVE/                        # 8 CSV
└── Datacorregida/                                 # parquet por día
```

Los scripts reciben la carpeta como argumento: no dependen de este nombre.

## Comandos

Todos desde `vigia/`.

| Para reproducir | Comando |
|---|---|
| Split aleatorio contra temporal (tabla de `dup.cross_split`) | `python benchmarks/cic_split_experiment.py <8 CSV>` |
| Original contra corregido | `python benchmarks/cic_original_vs_corregido.py <dir original> <dir corregido>` |
| A, B y C de R9 (semilla 42) | `python benchmarks/cic_antes_despues.py <carpeta TrafficLabelling>` |
| A y B con 10 semillas | `python benchmarks/cic_semillas.py <carpeta TrafficLabelling> 10` |
| C con 10 semillas | `python benchmarks/cic_semillas.py <carpeta TrafficLabelling> 10 --solo-c` |
| Deriva entre los cinco días | `python benchmarks/cic_deriva_real.py <dir con los CSV por día>` |
| Envenenamiento sobre tráfico real | `python benchmarks/cic_envenenamiento_real.py <dir con los CSV por día>` |
| Ruido de etiqueta de Engelen | `python benchmarks/cic_ruido_engelen.py <dir del corregido>` |
| Control de falsos positivos | `python benchmarks/control_limpio.py out/control_limpio.parquet` |
| Escala (1 M a 25 M de filas) | `python benchmarks/escala.py` |

Los datasets de la sección "Auditorías sobre datasets reales" se auditan con la
CLI y el perfil correspondiente, por ejemplo
`vigia audit <carpeta> --profile cic-ids-2017`. Los perfiles son
`cic-ids-2017`, `cse-cic-ids-2018`, `unsw-nb15`, `unsw-nb15-raw`, `ugr-16` y
`ctu-13` (ver [`USO.md`](USO.md)).

## Qué esperar

- **Cifras exactas:** las de C (recall 0,00), los conteos de duplicados y los
  de validez. Si no coinciden, es un hallazgo.
- **Cifras que varían:** A y B del experimento R9. Cambian con la semilla y con
  detalles mínimos de los datos; por eso se publican con 10 semillas y no con
  un número único. No esperes reproducir el valor de la semilla 42 con otras
  versiones de LightGBM, sí rangos parecidos.
