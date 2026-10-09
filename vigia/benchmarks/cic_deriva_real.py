"""Mide deriva real entre los días de captura de CIC-IDS2017.

Hasta ahora el módulo 3 estaba medido solo contra deriva simulada: se tomaba un
dataset, se le desplazaba una columna a propósito y se comprobaba que el PSI
subiera. Eso verifica que la métrica está bien implementada, pero no dice nada
sobre si los umbrales sirven con tráfico de verdad.

Los cinco días de CIC-IDS2017 son una serie temporal genuina: la misma red, la
misma instrumentación, días distintos. El lunes es enteramente benigno; del
martes al viernes hay ataques. Comparar cada día contra el lunes es medir
deriva real, con una expectativa clara contra la cual contrastar:

  - lunes barajado contra si mismo -> sin deriva (control negativo)
  - lunes manana contra lunes tarde -> deriva intradia, si la hay
  - martes..viernes vs lunes -> deriva real, con clases que el lunes no tenia

Los dos controles importan tanto como el resto. El barajado es el que tiene que
dar limpio: si reporta deriva entre dos muestras aleatorias del mismo dia, los
umbrales estan mal calibrados y todo lo demas sobra.

El corte por mitades es distinto, y la primera vez que se corrio este benchmark
dio AUC 0,873 -- mas que martes contra lunes. No era un fallo: los archivos
vienen en orden temporal, asi que esa comparacion es la manana del lunes contra
la tarde, y el trafico de oficina cambia entre una y otra. Se deja como segundo
control justamente porque muestra que el modulo detecta deriva que nadie
inyecto, y que el corte de una comparacion la define por completo.

Uso:
    python benchmarks/cic_deriva_real.py <dir con los CSV por dia>
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

import vigia
from vigia.core.engine import run_audit
from vigia.core.findings import Report
from vigia.io.readers import read_dataset, strip_column_names

#: Nombre del día segun el archivo. El viernes va primero porque
#: `Portscan-DDos-Botnet-Friday` contiene "dos", que tambien marca al miercoles.
DAY_MARKERS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("friday", "portscan", "botnet"), "viernes"),
    (("monday",), "lunes"),
    (("tuesday", "bruteforce"), "martes"),
    (("wednesday",), "miercoles"),
    (("thursday", "infiltration", "webattack"), "jueves"),
)

ORDEN = ("lunes", "martes", "miercoles", "jueves", "viernes")

SEED = 42

#: Se muestrea cada día a este tamaño. Los detectores de deriva ya muestrean
#: internamente a 50.000 filas; hacerlo acá además iguala el tamaño de los dos
#: lados de la comparación, que es lo correcto: un lote de 500.000 filas contra
#: una referencia de 200.000 introduce diferencias de resolución que no son
#: deriva.
SAMPLE = 40_000


def _day_of(filename: str) -> str:
    low = filename.lower()
    for markers, day in DAY_MARKERS:
        if any(m in low for m in markers):
            return day
    raise SystemExit(f"No se pudo determinar el dia de captura de {filename!r}")


def load_days(folder: Path) -> dict[str, pl.DataFrame]:
    """Un DataFrame por día, concatenando los archivos que caen en el mismo."""
    por_dia: dict[str, list[pl.DataFrame]] = {}
    for f in sorted(folder.rglob("*")):
        if f.is_file() and f.suffix.lower() in (".csv", ".parquet"):
            df = strip_column_names(read_dataset(f))
            por_dia.setdefault(_day_of(f.name), []).append(df)

    if not por_dia:
        raise SystemExit(f"No hay CSV ni Parquet en {folder}")

    salida: dict[str, pl.DataFrame] = {}
    for dia in ORDEN:
        if dia not in por_dia:
            continue
        combinado = pl.concat(por_dia[dia], how="diagonal_relaxed")
        # `__source_file` es interna del lector: si sobrevive, el check de
        # esquema la ve como una columna mas y reporta deriva inexistente.
        combinado = combinado.drop(
            [c for c in combinado.columns if c.startswith("__")], strict=False
        )
        salida[dia] = combinado
        print(f"  {dia:10} {combinado.height:>9,} filas x {combinado.width:>3} cols")
    return salida


def _muestra(df: pl.DataFrame, n: int, seed: int) -> pl.DataFrame:
    if df.height <= n:
        return df
    return df.sample(n=n, seed=seed)


def medir(
    actual: pl.DataFrame, referencia: pl.DataFrame, tmp: Path, *, seed: int = SEED
) -> Report:
    """Corre el módulo de deriva de `actual` contra `referencia`."""
    tmp.parent.mkdir(parents=True, exist_ok=True)
    _muestra(actual, SAMPLE, seed).write_parquet(tmp)

    ctx = vigia.load(tmp, label_col="Label")
    ctx.reference = _muestra(referencia, SAMPLE, seed)
    report = run_audit(ctx, module="drift")
    tmp.unlink()
    return report


def resumir(report: Report) -> str:
    """Una línea con el semáforo y los hallazgos por check."""
    por_check = sorted(f.check_id.removeprefix("drift.") for f in report.findings)
    detalle = ", ".join(por_check) if por_check else "-"
    return f"{report.traffic_light().upper():9} {detalle}"


def _auc(report: Report) -> str:
    for f in report.findings:
        if f.check_id == "drift.covariate":
            return f"{f.metric.get('auc', 0.0):.3f}"
    return "<0.75"


def _n_psi(report: Report) -> str:
    for f in report.findings:
        if f.check_id == "drift.feature":
            return str(int(f.metric.get("n_columnas_derivadas", 0)))
    return "0"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    print("DIAS DE CAPTURA")
    dias = load_days(Path(sys.argv[1]))
    if "lunes" not in dias:
        raise SystemExit("hace falta el lunes: es la referencia de todas las comparaciones")

    tmp = Path("out/_tmp_deriva.parquet")
    lunes = dias["lunes"]

    print(f"\n{'=' * 74}\nCONTROLES SOBRE EL LUNES\n{'=' * 74}")
    mitad = lunes.height // 2

    # El que tiene que dar limpio: dos muestras aleatorias del mismo dia no se
    # diferencian en nada, asi que cualquier hallazgo aca es un falso positivo.
    barajado = lunes.sample(fraction=1.0, shuffle=True, seed=SEED)
    control = medir(barajado[:mitad], barajado[mitad:], tmp)
    print(f"  barajado (control negativo)   {resumir(control)}")
    print(f"    AUC: {_auc(control)}   columnas con PSI alto: {_n_psi(control)}")

    # Los archivos vienen en orden temporal, asi que esto es manana vs tarde.
    intradia = medir(lunes[:mitad], lunes[mitad:], tmp)
    print(f"\n  manana vs tarde (mismo dia)   {resumir(intradia)}")
    print(f"    AUC: {_auc(intradia)}   columnas con PSI alto: {_n_psi(intradia)}")

    print(f"\n{'=' * 74}\nDERIVA REAL: cada dia contra el lunes\n{'=' * 74}")
    print("  El lunes es 100% benigno. Cada dia siguiente trae ataques nuevos.\n")
    print(f"  {'comparacion':28} {'semaforo':9} {'AUC':>6} {'PSI':>4}  hallazgos")
    print(f"  {'-' * 70}")

    resultados: dict[str, Report] = {}
    for dia in ORDEN[1:]:
        if dia not in dias:
            continue
        r = medir(dias[dia], lunes, tmp)
        resultados[dia] = r
        checks = ", ".join(sorted(f.check_id.removeprefix("drift.") for f in r.findings))
        print(
            f"  {dia + ' vs lunes':28} {r.traffic_light().upper():9} "
            f"{_auc(r):>6} {_n_psi(r):>4}  {checks or '-'}"
        )

    print(f"\n{'=' * 74}\nDETALLE POR DIA\n{'=' * 74}")
    for dia, r in resultados.items():
        print(f"\n  {dia.upper()} contra el lunes")
        for f in r.sorted_findings():
            print(f"    {f.severity:8} {f.check_id:16} {f.title[:64]}")
        for cid, motivo in sorted(r.skipped.items()):
            print(f"    [no corrio] {cid}: {motivo}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
