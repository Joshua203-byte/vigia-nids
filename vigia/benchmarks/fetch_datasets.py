"""Descarga datasets públicos de NIDS para probar Vigía contra datos reales.

No inventa datos: baja los archivos tal como los publican sus autores y los
deja en `data/`. Lo único que agrega es la cabecera de columnas de NSL-KDD,
que el archivo `.txt` no trae y que se extrae del `.arff` del mismo repo.

Uso:

    python benchmarks/fetch_datasets.py            # lista lo disponible
    python benchmarks/fetch_datasets.py nsl-kdd    # descarga uno
    python benchmarks/fetch_datasets.py --all
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

#: Los `.txt` de NSL-KDD vienen sin cabecera; los nombres están en el `.arff`.
_NSL_BASE = "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master"
_NSL_ARFF = f"{_NSL_BASE}/KDDTrain%2B.arff"

#: El `.txt` trae una columna extra al final que el `.arff` no declara: el
#: nivel de dificultad, que los autores agregaron para medir cuántos modelos
#: acertaban cada fila. No es una característica del tráfico.
_NSL_EXTRA_COL = "difficulty"


@dataclass
class Dataset:
    """Un dataset descargable y cómo auditarlo."""

    key: str
    name: str
    files: dict[str, str]  # nombre local -> URL
    note: str
    audit_hint: str
    known_issues: list[str] = field(default_factory=list)


CATALOG: dict[str, Dataset] = {
    "nsl-kdd": Dataset(
        key="nsl-kdd",
        name="NSL-KDD",
        files={
            "KDDTrain+.txt": f"{_NSL_BASE}/KDDTrain%2B.txt",
            "KDDTest+.txt": f"{_NSL_BASE}/KDDTest%2B.txt",
        },
        note="~24 MB. Es KDD'99 con los duplicados quitados a propósito.",
        audit_hint="vigia audit data/nsl-kdd/nsl_kdd.csv --label-col class --split-col split",
        known_issues=[
            "Los autores lo crearon justamente para eliminar los duplicados "
            "masivos de KDD'99, así que dup.exact debería encontrar MUY POCO. "
            "Si encuentra mucho, el que está mal es Vigía.",
            "No tiene columna de tiempo ni de IP: leak.temporal y leak.host "
            "deben saltarse, y el semáforo debe dar gris si no hay hallazgos.",
            "El split oficial train/test tiene clases de ataque en test que no "
            "están en train: es deliberado, mide generalización.",
        ],
    ),
}


def _get(url: str, dest: Path, *, label: str) -> None:
    """Descarga ``url`` a ``dest`` mostrando el avance."""
    if dest.exists():
        print(f"  {label}: ya está ({dest.stat().st_size:,} bytes), no se vuelve a bajar")
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".parcial")
    print(f"  {label}: descargando…", end="", flush=True)
    try:
        # Sin User-Agent algunos servidores académicos responden 403.
        req = urllib.request.Request(url, headers={"User-Agent": "vigia-benchmarks/0.1"})
        with urllib.request.urlopen(req, timeout=120) as r, tmp.open("wb") as fh:
            while chunk := r.read(1 << 16):
                fh.write(chunk)
    except (urllib.error.URLError, TimeoutError) as exc:
        tmp.unlink(missing_ok=True)
        print(f" falló: {exc}")
        raise SystemExit(
            f"\nNo se pudo descargar {url}\n"
            "Si el enlace cambió, bajalo a mano y dejalo en la carpeta data/."
        ) from exc

    tmp.replace(dest)
    print(f" listo ({dest.stat().st_size:,} bytes)")


def _nsl_column_names() -> list[str]:
    """Lee los nombres de columna de la cabecera del .arff de NSL-KDD.

    Se extraen del archivo en vez de escribirlos a mano: si el repo cambia,
    el error salta acá y no como un desalineamiento silencioso de columnas.
    """
    req = urllib.request.Request(_NSL_ARFF, headers={"User-Agent": "vigia-benchmarks/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        head = r.read(1 << 16).decode("utf-8", errors="replace")

    names = re.findall(r"@attribute\s+'([^']+)'", head, flags=re.IGNORECASE)
    if len(names) != 42:
        raise SystemExit(
            f"El .arff de NSL-KDD declaró {len(names)} columnas y se esperaban 42. "
            "El repositorio cambió: revisá el formato antes de seguir."
        )
    return [*names, _NSL_EXTRA_COL]


def _prepare_nsl_kdd(out_dir: Path) -> Path:
    """Junta train y test en un CSV con cabecera y columna de split.

    NSL-KDD publica el split oficial en dos archivos separados. Para que Vigía
    pueda buscar fugas entre conjuntos hay que unirlos con una columna que diga
    de dónde viene cada fila, que es exactamente lo que haría quien entrena.
    """
    import polars as pl

    cols = _nsl_column_names()
    frames = []
    for split, fname in (("train", "KDDTrain+.txt"), ("test", "KDDTest+.txt")):
        df = pl.read_csv(
            out_dir / fname,
            has_header=False,
            new_columns=cols,
            infer_schema_length=10_000,
        )
        frames.append(df.with_columns(pl.lit(split).alias("split")))

    combined = pl.concat(frames)
    dest = out_dir / "nsl_kdd.csv"
    combined.write_csv(dest)
    print(f"  combinado: {dest.name} ({combined.height:,} filas × {combined.width} columnas)")
    return dest


def fetch(key: str) -> None:
    ds = CATALOG[key]
    out_dir = DATA_DIR / key
    print(f"\n{ds.name} — {ds.note}")
    for fname, url in ds.files.items():
        _get(url, out_dir / fname, label=fname)

    if key == "nsl-kdd":
        _prepare_nsl_kdd(out_dir)

    if ds.known_issues:
        print("\n  Qué esperar (según lo que publicaron sus autores):")
        for issue in ds.known_issues:
            print(f"    · {issue}")
    print(f"\n  Para auditarlo:\n    {ds.audit_hint}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", choices=sorted(CATALOG), help="cuál descargar")
    parser.add_argument("--all", action="store_true", help="descargar todos")
    args = parser.parse_args()

    if args.all:
        for key in CATALOG:
            fetch(key)
    elif args.dataset:
        fetch(args.dataset)
    else:
        print("Datasets disponibles:\n")
        for ds in CATALOG.values():
            print(f"  {ds.key:12} {ds.name} — {ds.note}")
        print("\nDescargar con: python benchmarks/fetch_datasets.py <nombre>")
        print("\nLos que necesitan registro manual (no se pueden automatizar):")
        print("  CIC-IDS2017          https://www.unb.ca/cic/datasets/ids-2017.html")
        print(
            "  CIC-IDS2017 corregido  https://www.kaggle.com/datasets/dhoogla/distrinetcicids2017"
        )
        print("  UNSW-NB15            https://research.unsw.edu.au/projects/unsw-nb15-dataset")
    return 0


if __name__ == "__main__":
    sys.exit(main())
