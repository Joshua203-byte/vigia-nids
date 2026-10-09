"""Mide los detectores de envenenamiento sobre CIC-IDS2017 real.

El modulo 2 estaba medido contra 3.000 filas sinteticas gaussianas. Ahi los
detectores daban precision y recall de 1,000, pero ese numero dice poco: en un
dataset sintetico las clases estan bien separadas y cualquier fila envenenada
sobresale. El trafico real tiene colas largas, columnas correlacionadas, clases
muy desbalanceadas y filas genuinamente raras que no son envenenamiento.

Aca el dataset es autentico y solo el envenenamiento es sintetico. Es lo que
propone la seccion 9.4 del diseno, y es la unica forma de medir: no existe un
dataset de NIDS con envenenamiento real etiquetado como tal, asi que sin una
verdad de referencia inyectada no se puede calcular precision ni recall.

Las tres inyecciones se miden por separado, y se corre ademas un control sobre
el dataset limpio: cuantas filas marca el sistema cuando no hay nada que
encontrar. Ese numero es el que decide si los detectores sirven en produccion.

Uso:
    python benchmarks/cic_envenenamiento_real.py <dir con los CSV por dia>
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

import vigia
from vigia.core.engine import run_audit
from vigia.io.readers import read_dataset, strip_column_names
from vigia.poison import (
    PoisonSpec,
    inject_backdoor,
    inject_label_flip,
    inject_synthetic,
    rank_suspects,
)

SEED = 42

#: Tamano de la muestra. Los detectores caros (`poison.knn`, `poison.cluster`)
#: muestrean internamente a 50.000 filas: pasarles mas no mejora la cobertura,
#: solo hace que los indices detectados cubran una fraccion menor del dataset y
#: el recall se subestime por muestreo en vez de por error del detector.
SAMPLE = 30_000

#: Porcentaje de filas envenenadas. 2% es el orden de magnitud que usa la
#: literatura: suficiente para mover un modelo, poco como para seguir siendo
#: una anomalia. Por encima del 10-15% deja de ser detectable por estos
#: metodos, porque lo envenenado pasa a ser el patron.
RATIO = 0.02

#: Cuantas filas revisa un analista. La pregunta real no es "cuantas encontro"
#: sino "de las 200 que voy a mirar a mano, cuantas valen la pena".
TOP = 200


def cargar(folder: Path) -> pl.DataFrame:
    """Una muestra de todos los dias, con las columnas internas fuera."""
    frames = []
    for f in sorted(folder.rglob("*")):
        if f.is_file() and f.suffix.lower() in (".csv", ".parquet"):
            frames.append(strip_column_names(read_dataset(f)))
    if not frames:
        raise SystemExit(f"No hay CSV ni Parquet en {folder}")

    df = pl.concat(frames, how="diagonal_relaxed")
    df = df.drop([c for c in df.columns if c.startswith("__")], strict=False)

    # Las filas sin etiqueta no sirven para medir: un detector no puede
    # acertar ni equivocarse sobre una fila cuya verdad no existe.
    df = df.filter(pl.col("Label").is_not_null())
    print(f"  dataset completo   {df.height:>9,} filas x {df.width} cols")

    muestra = df.sample(n=min(SAMPLE, df.height), seed=SEED, shuffle=True)
    print(f"  muestra de trabajo {muestra.height:>9,} filas")
    print("\n  clases en la muestra:")
    for fila in (
        muestra.group_by("Label").len().sort("len", descending=True).head(8).iter_rows()
    ):
        print(f"    {str(fila[0])[:36]:36} {fila[1]:>7,}")
    return muestra


def detectar(df: pl.DataFrame, tmp: Path) -> tuple[list[int], dict[str, list[int]]]:
    """Corre los cuatro detectores y devuelve el ranking y el detalle por check."""
    tmp.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(tmp)
    ctx = vigia.load(tmp, label_col="Label", seed=SEED)
    report = run_audit(ctx, module="poison")
    tmp.unlink()

    por_check: dict[str, list[int]] = {}
    for f in report.findings:
        if f.row_indices:
            por_check.setdefault(f.check_id, []).extend(f.row_indices)

    for cid, motivo in sorted(report.skipped.items()):
        print(f"      [no corrio] {cid}: {motivo}")

    combinado = [s.row for s in rank_suspects(report.findings, top=TOP, min_detectors=2)]
    return combinado, por_check


def evaluar(spec: PoisonSpec, tmp: Path, titulo: str) -> None:
    """Mide cada detector por separado y el combinado contra la verdad."""
    print(f"\n  {titulo}")
    print(f"    envenenadas: {spec.n_poisoned:,} de {spec.df.height:,} ({spec.ratio:.2%})")

    combinado, por_check = detectar(spec.df, tmp)

    print(f"\n    {'detector':18} {'marcadas':>9} {'precision':>10} {'recall':>8} {'F1':>7}")
    print(f"    {'-' * 56}")
    for cid in sorted(por_check):
        m = spec.evaluate(sorted(set(por_check[cid])))
        print(
            f"    {cid:18} {int(m['n_detectadas']):>9,} {m['precision']:>10.3f} "
            f"{m['recall']:>8.3f} {m['f1']:>7.3f}"
        )

    m = spec.evaluate(combinado)
    print(
        f"    {'combinado (top ' + str(TOP) + ')':18} {int(m['n_detectadas']):>9,} "
        f"{m['precision']:>10.3f} {m['recall']:>8.3f} {m['f1']:>7.3f}"
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    print("CIC-IDS2017")
    df = cargar(Path(sys.argv[1]))
    tmp = Path("out/_tmp_envenenamiento.parquet")

    clases = df.group_by("Label").len().sort("len", descending=True)
    mayoritaria = str(clases.row(0)[0])
    # La clase de ataque mas numerosa: envenenar desde una clase con 20 filas
    # mide el ruido del muestreo, no el detector.
    ataques = [
        str(r[0]) for r in clases.iter_rows() if str(r[0]).upper() != mayoritaria.upper()
    ]
    if not ataques:
        raise SystemExit("la muestra no tiene ninguna clase de ataque")
    ataque = ataques[0]
    print(f"\n  clase benigna: {mayoritaria}   clase de ataque usada: {ataque}")

    print(f"\n{'=' * 74}\nCONTROL: dataset limpio, sin envenenar\n{'=' * 74}")
    print("  Todo lo que marque aca es un falso positivo.\n")
    combinado, por_check = detectar(df, tmp)
    print(f"    {'detector':18} {'filas marcadas':>15}")
    print(f"    {'-' * 34}")
    for cid in sorted(por_check):
        print(f"    {cid:18} {len(set(por_check[cid])):>15,}")
    print(f"    {'combinado (>=2 det.)':18} {len(combinado):>15,}")

    print(f"\n{'=' * 74}\nLOS TRES ATAQUES\n{'=' * 74}")

    evaluar(
        inject_label_flip(df, "Label", ratio=RATIO, from_label=ataque,
                          to_label=mayoritaria, seed=SEED),
        tmp,
        f"1. CAMBIO DE ETIQUETA -- {ataque} marcado como {mayoritaria}",
    )

    # El trigger va en una columna con muchos valores posibles: en una binaria
    # cualquier valor supera el umbral de frecuencia global y no hay puerta
    # trasera que encontrar.
    numericas = [
        c
        for c in df.columns
        if df.schema[c].is_numeric() and df.get_column(c).n_unique() > 100
    ]
    if numericas:
        col = numericas[0]
        evaluar(
            inject_backdoor(df, "Label", col, trigger_value=31337.0,
                            target_label=mayoritaria, ratio=RATIO, seed=SEED),
            tmp,
            f"2. PUERTA TRASERA -- {col} = 31337 implica {mayoritaria}",
        )

    evaluar(
        inject_synthetic(df, "Label", n_rows=int(df.height * RATIO),
                         target_label=mayoritaria, source_label=ataque, seed=SEED),
        tmp,
        f"3. INYECCION SINTETICA -- copias de {ataque} etiquetadas {mayoritaria}",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
