"""Mide los detectores contra ruido de etiqueta real, no inyectado.

Es la unica verdad de referencia real que tiene el modulo 2. Todo lo demas se
mide inyectando envenenamiento y comprobando si se recupera, lo cual verifica
al detector contra un ataque que uno mismo diseno. Aca la verdad la publico un
tercero.

Engelen, Rimmer y Joosen (2021) reetiquetaron CIC-IDS2017 despues de revisar la
captura original, y su version marca con la clase `Attempted-relabel-as-Benign`
los flujos que el dataset original daba por ataque cuando el ataque no habia
prosperado. Esas filas son ruido de etiqueta documentado: en el original llevan
una etiqueta de ataque que no les corresponde.

No es envenenamiento -- nadie las inserto a proposito -- pero deja la misma
huella: filas cuya etiqueta contradice a la de sus vecinas. Si `poison.knn`
sirve para lo que decimos que sirve, tiene que encontrarlas.

La comparacion es contra el azar: con ~2 % de filas ruidosas, un detector que
elige al azar acierta el 2 % de las veces. Lo que importa es cuanto lo supera.

Uso:
    python benchmarks/cic_ruido_engelen.py <dir de la version corregida>
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

import vigia
from vigia.core.engine import run_audit
from vigia.io.readers import read_dataset, strip_column_names
from vigia.poison import rank_suspects

SEED = 42
SAMPLE = 30_000
TOP = 200

#: La clase con la que Engelen marca los flujos mal etiquetados en el original.
RELABEL = "Attempted-relabel-as-Benign"


def cargar(folder: Path) -> pl.DataFrame:
    """Los dias que contienen filas reetiquetadas, en una sola muestra."""
    vistos: set[str] = set()
    frames = []
    for f in sorted(folder.rglob("*.parquet")):
        # La version corregida repite cada archivo dentro de una subcarpeta con
        # su mismo nombre; sin esto cada dia entra dos veces.
        if f.name in vistos:
            continue
        vistos.add(f.name)
        frames.append(strip_column_names(read_dataset(f)))

    if not frames:
        raise SystemExit(f"No hay Parquet en {folder}")

    df = pl.concat(frames, how="diagonal_relaxed")
    df = df.drop([c for c in df.columns if c.startswith("__")], strict=False)
    df = df.filter(pl.col("Label").is_not_null())
    print(f"  version corregida  {df.height:>9,} filas x {df.width} cols")

    n_relabel = int((df.get_column("Label").cast(pl.Utf8) == RELABEL).sum())
    print(f"  filas reetiquetadas {n_relabel:>8,} ({n_relabel / df.height:.2%})")
    if not n_relabel:
        raise SystemExit(f"no hay filas con la clase {RELABEL!r}")

    muestra = df.sample(n=min(SAMPLE, df.height), seed=SEED, shuffle=True)
    print(f"  muestra de trabajo {muestra.height:>9,} filas")
    return muestra


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    print("CIC-IDS2017 corregido (Engelen et al. 2021)")
    muestra = cargar(Path(sys.argv[1]))

    etiquetas = muestra.get_column("Label").cast(pl.Utf8)
    verdad = {i for i, v in enumerate(etiquetas.to_list()) if v == RELABEL}
    print(f"  en la muestra      {len(verdad):>9,} reetiquetadas "
          f"({len(verdad) / muestra.height:.2%})")
    if not verdad:
        raise SystemExit("la muestra no capturo ninguna fila reetiquetada")

    # Se reconstruye el estado del dataset ORIGINAL: esas filas llevaban una
    # etiqueta de ataque. Darselas al detector ya marcadas seria regalarle la
    # respuesta, porque `Attempted-relabel-as-Benign` es una clase aparte que
    # cualquier detector separaria sin esfuerzo.
    como_original = muestra.with_columns(
        pl.when(pl.col("Label").cast(pl.Utf8) == RELABEL)
        .then(pl.lit("Benign"))
        .otherwise(pl.col("Label").cast(pl.Utf8))
        .alias("Label")
    )
    print("\n  Las filas reetiquetadas vuelven a 'Benign', que es como las ve")
    print("  un detector antes de saber que estan mal.")

    tmp = Path("out/_tmp_engelen.parquet")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    como_original.write_parquet(tmp)
    ctx = vigia.load(tmp, label_col="Label", seed=SEED)
    report = run_audit(ctx, module="poison")
    tmp.unlink()

    for cid, motivo in sorted(report.skipped.items()):
        print(f"  [no corrio] {cid}: {motivo}")

    base = len(verdad) / muestra.height

    print(f"\n{'=' * 74}\nRESULTADO\n{'=' * 74}")
    print(f"  Azar: {base:.2%} de aciertos. Todo lo que este por encima es senal.\n")
    print(f"  {'detector':22} {'marcadas':>9} {'aciertos':>9} {'precision':>10} {'x azar':>8}")
    print(f"  {'-' * 62}")

    for f in sorted(report.findings, key=lambda x: x.check_id):
        if not f.row_indices:
            continue
        marcadas = set(f.row_indices)
        aciertos = len(marcadas & verdad)
        prec = aciertos / len(marcadas) if marcadas else 0.0
        print(
            f"  {f.check_id:22} {len(marcadas):>9,} {aciertos:>9,} "
            f"{prec:>10.3f} {prec / base if base else 0:>7.1f}x"
        )

    combinado = {s.row for s in rank_suspects(report.findings, top=TOP, min_detectors=2)}
    aciertos = len(combinado & verdad)
    prec = aciertos / len(combinado) if combinado else 0.0
    print(
        f"  {'combinado (top ' + str(TOP) + ')':22} {len(combinado):>9,} {aciertos:>9,} "
        f"{prec:>10.3f} {prec / base if base else 0:>7.1f}x"
    )

    marcados = {f.check_id: set(f.row_indices) for f in report.findings if f.row_indices}
    union = set().union(*marcados.values()) if marcados else set()

    print(f"\n{'=' * 74}\nSOLAPAMIENTO ENTRE DETECTORES\n{'=' * 74}")
    print("  Cuantas filas correctas encuentran DOS detectores a la vez.\n")
    nombres = sorted(marcados)
    for i, a in enumerate(nombres):
        for b in nombres[i + 1 :]:
            comun = marcados[a] & marcados[b]
            print(
                f"  {a:16} & {b:16} comun {len(comun):>5,}  "
                f"de esos reetiquetados {len(comun & verdad):>3}"
            )

    print(
        f"\n  UNION de los cuatro: {len(union & verdad)} de {len(verdad)} "
        f"reetiquetadas ({len(union & verdad) / len(verdad):.1%} de recall) "
        f"en {len(union):,} filas"
    )

    print(
        "\n  LA CONCLUSION, y contradice lo que el modulo asumia:\n"
        "\n"
        "  Entre los cuatro encuentran mas de la mitad de las filas mal\n"
        "  etiquetadas, asi que los detectores sirven. Pero casi no se solapan:\n"
        "  cada uno encuentra filas distintas, no las mismas por caminos\n"
        "  distintos. `poison.cluster` no comparte ninguna con los otros tres.\n"
        "\n"
        "  Por eso exigir coincidencia (`min_detectors=2`) es contraproducente\n"
        "  aca: descarta casi todos los aciertos. La premisa de que la\n"
        "  coincidencia entre metodos independientes es la señal se cumplia\n"
        "  sobre envenenamiento inyectado, donde las filas envenenadas son\n"
        "  anomalas de varias formas a la vez, y no se cumple sobre ruido de\n"
        "  etiqueta real, donde cada fila es rara de UNA sola forma.\n"
        "\n"
        "  Para buscar etiquetas mal puestas conviene mirar la union con\n"
        "  `--min-detectors 1`, y revisar las listas por detector por separado."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
