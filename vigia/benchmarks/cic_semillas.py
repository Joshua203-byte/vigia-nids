"""Dispersión de A y B de R9 con varias semillas.

`cic_antes_despues.py` publica un único número por escenario con SEED = 42. Pero
A y B resultaron inestables (RESULTADOS.md, "Por qué cambiaron A y B"), así que
un número solo no dice cuánto hay que creerle. Este script repite A y B con
varias semillas y resume la dispersión. La semilla cambia a la vez el split
aleatorio y el modelo (`random_state` de LightGBM).

C se repite con `--solo-c`: el corte temporal no depende de la semilla del split,
pero el modelo sí, y que el cero de C aguante distintas semillas del modelo hay
que medirlo, no suponerlo.

Uso:
    python benchmarks/cic_semillas.py <carpeta con los CSVs> [n_semillas]
    python benchmarks/cic_semillas.py <carpeta con los CSVs> [n_semillas] --solo-c
"""

from __future__ import annotations

import statistics
import sys
from dataclasses import replace
from pathlib import Path

import polars as pl

from vigia.benchmark import evaluate
from vigia.fixes import apply_fix

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cic_antes_despues as base_script  # noqa: E402

GRANDES = ("BENIGN", "DoS Hulk", "PortScan", "DDoS")


def _aleatorio(df: pl.DataFrame, seed: int) -> pl.DataFrame:
    shuffled = df.sample(fraction=1.0, shuffle=True, seed=seed)
    n_train = int(shuffled.height * 0.7)
    return shuffled.with_columns(
        pl.when(pl.int_range(pl.len()) < n_train)
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias("split")
    )


def _resumen(nombre: str, valores: list[float]) -> str:
    sd = statistics.stdev(valores) if len(valores) > 1 else 0.0
    return (
        f"{nombre:28}{statistics.mean(valores):>9.4f}{sd:>9.4f}"
        f"{min(valores):>9.4f}{max(valores):>9.4f}"
    )


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--solo-c"]
    solo_c = "--solo-c" in sys.argv
    if not args:
        print(__doc__)
        return 2
    n = int(args[1]) if len(args) > 1 else 10
    semillas = list(range(1, n + 1))

    print("Leyendo...")
    datos = base_script.load(Path(args[0]))

    claves = ("C",) if solo_c else ("A", "B")
    filas: dict[str, dict[int, dict[str, float]]] = {c: {} for c in claves}
    for seed in semillas:
        if solo_c:
            previo = base_script._ctx(base_script.split_temporal(datos))
            sin_ids = apply_fix(previo, "drop_identifiers")
            m_c = evaluate(replace(base_script._ctx(sin_ids.df), seed=seed))
            fila = {"F1 macro": m_c.f1_macro, "FP/10k": m_c.fp_per_10k_benign or float("nan")}
            for clase in GRANDES:
                fila[f"recall {clase}"] = m_c.per_class_recall.get(clase, float("nan"))
            filas["C"][seed] = fila
            print(f"  semilla {seed:>2}: C F1 {m_c.f1_macro:.4f}", flush=True)
            continue
        ctx_a = replace(base_script._ctx(_aleatorio(datos, seed)), seed=seed)
        m_a = evaluate(ctx_a)
        sin_ids = apply_fix(ctx_a, "drop_identifiers")
        ctx_b = replace(base_script._ctx(sin_ids.df), seed=seed)
        m_b = evaluate(ctx_b)
        for clave, m in (("A", m_a), ("B", m_b)):
            fila = {"F1 macro": m.f1_macro, "FP/10k": m.fp_per_10k_benign or float("nan")}
            for clase in GRANDES:
                fila[f"recall {clase}"] = m.per_class_recall.get(clase, float("nan"))
            filas[clave][seed] = fila
        print(
            f"  semilla {seed:>2}: A F1 {m_a.f1_macro:.4f}  B F1 {m_b.f1_macro:.4f}"
            f"  B recall DDoS {m_b.per_class_recall.get('DDoS', float('nan')):.4f}",
            flush=True,
        )

    print(f"\n{n} semillas ({semillas[0]} a {semillas[-1]})\n")
    for clave in claves:
        print(f"{clave}.   {'media':>9}{'desv.':>9}{'mín':>9}{'máx':>9}")
        for metrica in filas[clave][semillas[0]]:
            vals = [filas[clave][s][metrica] for s in semillas]
            print(_resumen(metrica, vals))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
