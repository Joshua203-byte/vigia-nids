"""Compara CIC-IDS2017 original contra la versión corregida de Engelen et al.

La pregunta que responde: los defectos que Vigía encuentra en el original,
¿desaparecen en la versión que los autores corrigieron? Si desaparecen, la
herramienta está midiendo lo que dice medir. Si no, o la corrección no los
cubría o Vigía los está inventando — y en cualquier caso hay que saberlo.

Referencia: Engelen, Rimmer y Joosen (2021), "Troubleshooting an Intrusion
Detection Dataset: the CICIDS2017 Case Study".

Uso:
    python benchmarks/cic_original_vs_corregido.py <dir original> <dir corregido>
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

import vigia
from vigia.core.findings import Report
from vigia.io.readers import read_dataset, strip_column_names

#: Día de captura según el nombre del archivo, en las dos versiones: la
#: corregida renombra los archivos por el ataque que contienen.
#:
#: El orden importa y los marcadores del viernes van primero: el nombre
#: `Portscan-DDos-Botnet-Friday` contiene "dos", que también es el marcador del
#: miércoles (`DoS-Wednesday`). Con el orden inverso el viernes se asignaba al
#: día 3 y desaparecía de la comparación, llevándose consigo casi todos los
#: ataques del dataset.
DAY_MARKERS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("friday", "portscan", "botnet"), 5),
    (("monday",), 1),
    (("tuesday", "bruteforce"), 2),
    (("wednesday",), 3),
    (("thursday", "infiltration", "webattack"), 4),
)

SEED = 42
TEMPORAL_CUTOFF = 3


def _day_of(filename: str) -> int:
    low = filename.lower()
    for markers, day in DAY_MARKERS:
        if any(m in low for m in markers):
            return day
    raise SystemExit(f"No se pudo determinar el día de captura de {filename!r}")


def _collect(folder: Path) -> list[Path]:
    """Un archivo por día: la versión corregida repite algunos en subcarpetas."""
    found: dict[int, Path] = {}
    for f in sorted(folder.rglob("*")):
        if f.is_file() and f.suffix.lower() in (".csv", ".parquet"):
            found.setdefault(_day_of(f.name), f)
    if not found:
        raise SystemExit(f"No hay CSV ni Parquet en {folder}")
    return [found[d] for d in sorted(found)]


def load_version(folder: Path, label: str) -> pl.DataFrame:
    print(f"\n{label}")
    frames = []
    for f in _collect(folder):
        df = strip_column_names(read_dataset(f))
        day = _day_of(f.name)
        frames.append(df.with_columns(pl.lit(day).alias("capture_day")))
        print(f"  día {day}  {df.height:>9,} filas × {df.width:>3} cols  {f.name[:52]}")

    combined = pl.concat(frames, how="diagonal_relaxed")
    print(f"  {'total':>5}  {combined.height:>9,} filas × {combined.width} columnas")
    return combined


def audit_with_split(df: pl.DataFrame, *, random_split: bool, tmp: Path) -> Report:
    """Audita el DataFrame con una de las dos formas de partirlo."""
    if random_split:
        shuffled = df.sample(fraction=1.0, shuffle=True, seed=SEED)
        n_train = int(shuffled.height * 0.7)
        prepared = shuffled.with_columns(
            pl.when(pl.int_range(pl.len()) < n_train)
            .then(pl.lit("train"))
            .otherwise(pl.lit("test"))
            .alias("split")
        )
    else:
        prepared = df.with_columns(
            pl.when(pl.col("capture_day") <= TEMPORAL_CUTOFF)
            .then(pl.lit("train"))
            .otherwise(pl.lit("test"))
            .alias("split")
        )

    tmp.parent.mkdir(parents=True, exist_ok=True)
    prepared.write_parquet(tmp)
    report = vigia.audit(vigia.load(tmp, label_col="Label", split_col="split"))
    tmp.unlink()
    return report


def summarize(report: Report, title: str) -> dict[str, int]:
    """Imprime el reporte y devuelve el conteo de hallazgos por check."""
    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.check_id] = counts.get(f.check_id, 0) + 1

    print(f"\n  {title}")
    print(f"    semáforo: {report.traffic_light().upper()}  {report.counts()}")
    for f in report.sorted_findings():
        if f.severity in ("critical", "high"):
            print(f"      {f.severity:8} {f.check_id:26} {f.title[:56]}")
    # Sin esto, un check que no pudo correr se confunde con uno que corrió y
    # no encontró nada: exactamente la conclusión falsa que hay que evitar.
    for cid, reason in sorted(report.skipped.items()):
        print(f"      [no corrió] {cid}: {reason}")
    return counts


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    original = load_version(Path(sys.argv[1]), "ORIGINAL")
    corregido = load_version(Path(sys.argv[2]), "CORREGIDO (Engelen et al.)")

    tmp = Path("out/_tmp_comparacion.parquet")
    results: dict[str, dict[str, int]] = {}
    skipped: dict[str, set[str]] = {}

    for name, df in (("original", original), ("corregido", corregido)):
        print(f"\n{'=' * 74}\n{name.upper()}\n{'=' * 74}")
        for split_name, is_random in (("split aleatorio", True), ("split temporal", False)):
            key = f"{name} / {split_name}"
            report = audit_with_split(df, random_split=is_random, tmp=tmp)
            results[key] = summarize(report, split_name)
            skipped[key] = set(report.skipped)

    print(f"\n{'=' * 74}\nCOMPARACIÓN\n{'=' * 74}")
    print("  n = cantidad de hallazgos    · = el check no pudo correr\n")
    all_checks = sorted(
        {c for counts in results.values() for c in counts}
        | {c for s in skipped.values() for c in s}
    )
    headers = list(results)
    print(f"{'check':26}" + "".join(f"{h[:21]:>23}" for h in headers))
    for check in all_checks:
        cells = []
        for h in headers:
            cells.append("·" if check in skipped[h] else str(results[h].get(check, 0)))
        print(f"{check:26}" + "".join(f"{c:>23}" for c in cells))

    return 0


if __name__ == "__main__":
    sys.exit(main())
