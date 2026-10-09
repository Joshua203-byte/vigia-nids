"""El experimento central: ¿detecta Vigía la diferencia entre un split bueno y uno malo?

CIC-IDS2017 no trae columna de split, así que cada quien la inventa. Casi
toda la literatura parte el dataset al azar, que mezcla los días de captura
entre entrenamiento y prueba. La alternativa correcta es cortar por tiempo:
entrenar con los primeros días y evaluar con los últimos.

Este script arma las dos versiones a partir de los mismos datos y audita cada
una. Si Vigía sirve, la primera tiene que salir mucho peor que la segunda.

Uso:
    python benchmarks/cic_split_experiment.py <carpeta con los 8 CSVs>
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

import vigia
from vigia.io.readers import read_dataset, strip_column_names

#: El orden de captura de CIC-IDS2017. El nombre del archivo es el único
#: registro del día en esta versión del dataset, que no trae timestamp.
DAY_ORDER: tuple[tuple[str, int], ...] = (
    ("Monday", 1),
    ("Tuesday", 2),
    ("Wednesday", 3),
    ("Thursday", 4),
    ("Friday", 5),
)

SEED = 42
#: Los tres primeros días entrenan, los dos últimos evalúan.
TEMPORAL_CUTOFF = 3


def _day_of(filename: str) -> int:
    for name, day in DAY_ORDER:
        if name.lower() in filename.lower():
            return day
    raise SystemExit(f"No se pudo determinar el día de captura de {filename!r}")


def load_days(folder: Path) -> pl.DataFrame:
    """Lee los CSVs agregando el día de captura de cada uno."""
    files = sorted(folder.glob("*.csv"))
    if not files:
        raise SystemExit(f"No hay CSVs en {folder}")

    frames = []
    for f in files:
        # Con el lector de Vigía, no con `pl.read_csv` directo: el día de
        # ataques web no viene en UTF-8 y solo el lector sabe sortearlo.
        df = strip_column_names(read_dataset(f))
        frames.append(df.with_columns(pl.lit(_day_of(f.name)).alias("capture_day")))
        print(f"  {f.name:58} día {_day_of(f.name)}  {df.height:>9,} filas")

    combined = pl.concat(frames, how="diagonal_relaxed")
    print(f"\n  total: {combined.height:,} filas × {combined.width} columnas")
    return combined


def audit_variant(df: pl.DataFrame, name: str, out_dir: Path) -> None:
    """Audita un DataFrame que ya trae su columna `split`."""
    tmp = out_dir / f"{name}.parquet"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(tmp)

    ctx = vigia.load(tmp, label_col="Label", split_col="split")
    report = vigia.audit(ctx)

    print(f"\n{'=' * 72}\n{name}\n{'=' * 72}")
    print(f"semáforo: {report.traffic_light().upper()}   {report.counts()}")
    for f in report.sorted_findings():
        print(f"  {f.severity:8} {f.check_id:26} {f.title[:58]}")
    for cid, reason in sorted(report.skipped.items()):
        print(f"  [saltado] {cid}: {reason}")

    from vigia.report import write_report

    write_report(report, out_dir / name)
    tmp.unlink()


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    folder = Path(sys.argv[1])
    out_dir = Path("out/cic-experimento")

    print("Leyendo los CSVs por día de captura…")
    df = load_days(folder)

    # Variante A: split aleatorio, lo que hace casi toda la literatura.
    # Mezcla los días, así que la prueba contiene tráfico simultáneo al
    # de entrenamiento e incluso anterior.
    shuffled = df.sample(fraction=1.0, shuffle=True, seed=SEED)
    n_train = int(shuffled.height * 0.7)
    aleatorio = shuffled.with_columns(
        pl.when(pl.int_range(pl.len()) < n_train)
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias("split")
    )

    # Variante B: corte temporal. Entrena con lunes-miércoles, evalúa con
    # jueves-viernes. Es lo que hace un NIDS en producción: predecir el futuro.
    temporal = df.with_columns(
        pl.when(pl.col("capture_day") <= TEMPORAL_CUTOFF)
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias("split")
    )

    audit_variant(aleatorio, "A-split-aleatorio", out_dir)
    audit_variant(temporal, "B-split-temporal", out_dir)

    print(f"\nReportes en {out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
