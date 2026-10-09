"""El dataset de control da verde con cada formato de entrada que Vigia lee.

`test_control_limpio.py` solo prueba Parquet. Un lector que cambiara un tipo,
dejara una columna constante o perdiera una columna haria saltar un check solo
con ciertos formatos; aqui se escribe el mismo control en cada uno.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import polars as pl
import pytest

import vigia

pytest.importorskip("cleanlab")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks"))

from control_limpio import build  # noqa: E402

N = 8_000
ROLES = dict(
    label_col="label",
    split_col="split",
    time_col="timestamp",
    src_ip_col="src_ip",
    dst_ip_col="dst_ip",
)


@pytest.fixture(scope="module")
def control() -> pl.DataFrame:
    return build(n=N)


def _epoch(df: pl.DataFrame) -> pl.DataFrame:
    return df.with_columns(pl.col("timestamp").dt.epoch("s").alias("timestamp"))


def _csv(df: pl.DataFrame, path: Path) -> dict:
    df.write_csv(path)
    return {}


def _parquet(df: pl.DataFrame, path: Path) -> dict:
    df.write_parquet(path)
    return {}


def _zeek_tsv(df: pl.DataFrame, path: Path) -> dict:
    rows = _epoch(df)
    types = []
    for c in rows.columns:
        d = rows.schema[c]
        types.append(
            "time"
            if c == "timestamp"
            else "count"
            if d.is_integer()
            else "double"
            if d.is_float()
            else "string"
        )
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        # Zeek declara el separador como texto escapado (barra, x, 0, 9), no como un tab.
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        f.write("#fields\t" + "\t".join(rows.columns) + "\n#types\t" + "\t".join(types) + "\n")
        rows.write_csv(f, separator="\t", include_header=False)
        f.write("#close\t2024-01-01-00-00-00\n")
    return {}


def _zeek_json(df: pl.DataFrame, path: Path) -> dict:
    with open(path, "w", encoding="utf-8") as f:
        for r in _epoch(df).iter_rows(named=True):
            f.write(json.dumps(r) + "\n")
    return {}


def _eve(df: pl.DataFrame, path: Path) -> dict:
    """Flujos EVE con las caracteristicas anidadas bajo `flow`, como las escribe Suricata."""
    with open(path, "w", encoding="utf-8") as f:
        for r in _epoch(df).iter_rows(named=True):
            o = {
                "event_type": "flow",
                "timestamp": r["timestamp"],
                "src_ip": r["src_ip"],
                "dest_ip": r["dst_ip"],
                "src_port": r["src_port"],
                "dest_port": r["dst_port"],
                "proto": r["protocol"],
                "flow": {k: v for k, v in r.items() if k.startswith("feature_")},
                "label": r["label"],
                "split": r["split"],
            }
            f.write(json.dumps(o) + "\n")
    return {"dst_ip_col": "dest_ip"}


FORMATOS = {
    "csv": (_csv, "c.csv"),
    "parquet": (_parquet, "c.parquet"),
    "zeek-tsv": (_zeek_tsv, "conn.log"),
    "zeek-json": (_zeek_json, "conn_json.log"),
    "suricata-eve": (_eve, "eve.json"),
}


@pytest.mark.parametrize("formato", FORMATOS)
def test_el_control_da_verde_en_cada_formato(formato, control, tmp_path):
    escribir, nombre = FORMATOS[formato]
    path = tmp_path / nombre
    extra = escribir(control, path)

    ctx = vigia.load(path, **{**ROLES, **extra})
    rep = vigia.audit(ctx)

    assert ctx.n_rows == N
    assert rep.findings == [], [(f.check_id, f.severity) for f in rep.findings]
    # Si los checks de fuga se saltaran, "verde" no probaria nada sobre ellos.
    for check in ("leak.host", "leak.session", "leak.temporal", "dup.cross_split"):
        assert check not in rep.skipped, (check, rep.skipped.get(check))
