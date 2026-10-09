"""Huellas de contenido: del archivo (reproducibilidad) y por fila (duplicados)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import polars as pl

_CHUNK = 1 << 20  # 1 MiB


def file_sha256(path: str | Path) -> str:
    """SHA-256 del archivo, para el anexo de reproducibilidad (sección 15.1)."""
    h = hashlib.sha256()
    p = Path(path)
    paths = sorted(p.rglob("*")) if p.is_dir() else [p]
    for f in paths:
        if not f.is_file():
            continue
        # El nombre entra en la huella para que reordenar archivos no pase inadvertido.
        h.update(f.name.encode("utf-8"))
        with f.open("rb") as fh:
            while chunk := fh.read(_CHUNK):
                h.update(chunk)
    return h.hexdigest()


def row_hashes(df: pl.DataFrame, columns: list[str] | None = None) -> pl.Series:
    """Hash por fila sobre ``columns`` (por defecto, todas).

    Usa ``hash_rows()`` nativo de Polars: no pasa por Python, así que el costo
    en tiempo y memoria es una fracción del de materializar la fila como texto
    (ver benchmarks/escala.py). Los valores del hash no son comparables con
    versiones anteriores de Vigía; solo se comparan entre sí dentro de una
    misma ejecución.
    """
    cols = columns if columns is not None else df.columns
    if not cols:
        # Sin columnas todas las filas son indistinguibles, así que comparten
        # hash. Devolver una Serie vacía en cambio rompería a quien la use
        # junto al DataFrame: las alturas no coincidirían.
        return pl.Series("row_hash", [0] * df.height, dtype=pl.UInt64)

    return df.select(cols).hash_rows().rename("row_hash")
