"""¿Cuánto del F1 de CIC-IDS2017 es real? (sección 8.8, requisito R9)

Entrena el mismo modelo tres veces sobre los mismos datos, cambiando solo cómo
se los prepara:

  A. Split aleatorio, todas las columnas. Lo que hace casi toda la literatura.
  B. Split aleatorio, sin las columnas identificadoras.
  C. Split temporal, sin las columnas identificadoras. Lo que mide TESSERACT.

La diferencia entre A y C es la parte del rendimiento que venía de los defectos
del dataset y no de haber aprendido a detectar ataques.

Uso:
    python benchmarks/cic_antes_despues.py <carpeta con los CSVs>
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

from vigia.benchmark import evaluate
from vigia.core.context import AuditContext
from vigia.fixes import apply_fix
from vigia.io.readers import read_dataset, strip_column_names

SEED = 42
TEMPORAL_CUTOFF = 3
DAY_MARKERS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("friday", "portscan", "botnet"), 5),
    (("monday",), 1),
    (("tuesday", "bruteforce"), 2),
    (("wednesday",), 3),
    (("thursday", "infiltration", "webattack"), 4),
)


def _day_of(filename: str) -> int:
    low = filename.lower()
    for markers, day in DAY_MARKERS:
        if any(m in low for m in markers):
            return day
    raise SystemExit(f"No se pudo determinar el día de {filename!r}")


def load(folder: Path) -> pl.DataFrame:
    frames = []
    for f in sorted(folder.rglob("*")):
        if f.is_file() and f.suffix.lower() in (".csv", ".parquet"):
            df = strip_column_names(read_dataset(f))
            frames.append(df.with_columns(pl.lit(_day_of(f.name)).alias("capture_day")))
            print(f"  día {_day_of(f.name)}  {df.height:>9,} filas  {f.name[:50]}")
    combined = pl.concat(frames, how="diagonal_relaxed")
    print(f"  total: {combined.height:,} filas x {combined.width} columnas\n")
    return combined


def _ctx(df: pl.DataFrame) -> AuditContext:
    """Contexto con las columnas de CIC-IDS2017 ya identificadas."""
    cols = set(df.columns)
    return AuditContext(
        df=df,
        label_col="Label",
        split_col="split" if "split" in cols else None,
        time_col="Timestamp" if "Timestamp" in cols else None,
        src_ip_col="Source IP" if "Source IP" in cols else None,
        dst_ip_col="Destination IP" if "Destination IP" in cols else None,
        src_port_col="Source Port" if "Source Port" in cols else None,
        dst_port_col="Destination Port" if "Destination Port" in cols else None,
        protocol_col="Protocol" if "Protocol" in cols else None,
        seed=SEED,
    )


def split_aleatorio(df: pl.DataFrame) -> pl.DataFrame:
    shuffled = df.sample(fraction=1.0, shuffle=True, seed=SEED)
    n_train = int(shuffled.height * 0.7)
    return shuffled.with_columns(
        pl.when(pl.int_range(pl.len()) < n_train)
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias("split")
    )


def split_temporal(df: pl.DataFrame) -> pl.DataFrame:
    return df.with_columns(
        pl.when(pl.col("capture_day") <= TEMPORAL_CUTOFF)
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias("split")
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    print("Leyendo...")
    base = load(Path(sys.argv[1]))

    escenarios = []

    # A: lo que hace casi toda la literatura.
    ctx_a = _ctx(split_aleatorio(base))
    escenarios.append(("A. Aleatorio, todas las columnas", ctx_a, evaluate(ctx_a)))

    # B: mismo split, sin las columnas que Vigía marca como identificadoras.
    sin_ids = apply_fix(ctx_a, "drop_identifiers")
    ctx_b = _ctx(sin_ids.df)
    escenarios.append(("B. Aleatorio, sin identificadoras", ctx_b, evaluate(ctx_b)))
    print(f"  ({sin_ids.summary})\n")

    # C: corte temporal y sin identificadoras: lo más cercano a producción.
    ctx_c_pre = _ctx(split_temporal(base))
    sin_ids_c = apply_fix(ctx_c_pre, "drop_identifiers")
    ctx_c = _ctx(sin_ids_c.df)
    escenarios.append(("C. Temporal, sin identificadoras", ctx_c, evaluate(ctx_c)))

    print("=" * 78)
    print(f"{'escenario':36}{'F1 macro':>11}{'exactitud':>12}{'FP/10k':>10}{'cols':>7}")
    print("=" * 78)
    for nombre, _, m in escenarios:
        fp = "-" if m.fp_per_10k_benign is None else f"{m.fp_per_10k_benign:.1f}"
        print(f"{nombre:36}{m.f1_macro:>11.4f}{m.accuracy:>12.4f}{fp:>10}{m.n_features:>7}")
    print("=" * 78)

    # El recall de los ataques grandes es lo comparable entre escenarios: el
    # F1 macro promedia por igual a Heartbleed (11 ejemplos) y a DoS Hulk
    # (231.073), así que un puñado de clases diminutas lo domina y esconde el
    # efecto que se quiere medir. Es justo lo que advierte `labels.imbalance`.
    grandes = ("BENIGN", "DoS Hulk", "PortScan", "DDoS")
    print("\nRecall de las clases con suficientes ejemplos:\n")
    print(f"{'clase':22}" + "".join(f"{n.split('.')[0]:>12}" for n, _, _ in escenarios))
    for clase in grandes:
        fila = "".join(
            f"{m.per_class_recall.get(clase, float('nan')):>12.4f}" for _, _, m in escenarios
        )
        print(f"{clase:22}{fila}")

    m_a, m_c = escenarios[0][2], escenarios[-1][2]
    print(
        f"\nFilas sin etiqueta descartadas del entrenamiento: {m_a.n_sin_etiqueta:,}"
        "\n(no se pueden usar ni para entrenar ni para evaluar)"
    )

    print("\n" + "=" * 78)
    print("LECTURA")
    print("=" * 78)
    print(
        "A vs B: quitar las columnas identificadoras cambia el resultado incluso\n"
        "  con el mismo split, porque el modelo estaba usando la IP y el ID de\n"
        "  flujo como si fueran características del tráfico.\n\n"
        "B vs C: es la comparación que importa. Mismo conjunto de columnas, lo\n"
        "  único que cambia es partir al azar o por día de captura. Todo lo que\n"
        "  se pierda al pasar de B a C era rendimiento que dependía de evaluar\n"
        "  con tráfico simultáneo al de entrenamiento.\n\n"
        "El F1 macro de los tres es bajo porque el dataset tiene 15 clases y\n"
        "  varias con menos de 40 ejemplos (Heartbleed: 11). Promediarlas por\n"
        "  igual hunde la métrica. La tabla de recall por clase de arriba es lo\n"
        "  que se puede comparar de verdad."
    )

    peor = min(m_c.per_class_recall.items(), key=lambda kv: kv[1])
    print(f"\nClase peor detectada en C: {peor[0]!r} con recall {peor[1]:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
