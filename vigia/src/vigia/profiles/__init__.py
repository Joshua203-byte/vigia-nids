"""Perfiles de datasets conocidos (sección 11.3 de vigia.md, requisito R17).

Un perfil es un YAML con metadatos verificados de un dataset público: qué
columna hace de rol (etiqueta, puerto destino, etc.), IPs atacantes
documentadas, ventanas horarias de cada ataque, y errores conocidos que
Vigía ya detecta. No reemplaza la detección automática de columnas: solo
evita que el usuario repita a mano lo que ya se sabe de un dataset conocido.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import polars as pl
import yaml

_PROFILES_DIR = Path(__file__).parent


class ProfileNotFound(Exception):
    """No existe un perfil con ese id."""


def available_profiles() -> list[str]:
    """Ids de los perfiles empaquetados con Vigía."""
    return sorted(p.stem for p in _PROFILES_DIR.glob("*.yaml"))


def load_profile(profile_id: str) -> dict[str, Any]:
    """Carga el YAML del perfil ``profile_id``.

    Lanza ``ProfileNotFound`` con la lista de ids disponibles en vez de dejar
    pasar el ``FileNotFoundError`` de Python, que no dice qué perfiles sí
    existen.
    """
    path = _PROFILES_DIR / f"{profile_id}.yaml"
    if not path.exists():
        disponibles = ", ".join(available_profiles()) or "ninguno"
        raise ProfileNotFound(f"no existe el perfil '{profile_id}' (disponibles: {disponibles})")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


#: Columna donde queda la etiqueta original cuando un perfil la agrupa. Empieza
#: con ``__`` para que Vigia no la cuente como caracteristica: si lo hiciera,
#: ``shortcut.single_feature`` la marcaria al 100 % por ser la etiqueta misma.
LABEL_ORIGINAL_COL = "__label_original"


def label_groups_expr(label_col: str, groups: dict[str, list[str]]) -> pl.Expr:
    """Expresion que reemplaza cada etiqueta por el grupo de su prefijo.

    ``groups`` es ``{grupo: [prefijo, ...]}``. Una etiqueta que no empieza con
    ningun prefijo queda como esta: nada se mezcla en silencio con otro grupo.
    """
    col = pl.col(label_col).cast(pl.Utf8)
    pairs = [(prefix, group) for group, prefixes in groups.items() for prefix in prefixes]
    expr = col
    # De atras hacia adelante, para que el primer prefijo de la lista gane.
    for prefix, group in reversed(pairs):
        expr = pl.when(col.str.starts_with(prefix)).then(pl.lit(group)).otherwise(expr)
    return expr


def apply_label_groups(
    df: pl.DataFrame, label_col: str, groups: dict[str, list[str]]
) -> pl.DataFrame:
    """Agrupa la etiqueta segun el perfil y guarda la original en ``__label_original``."""
    return df.with_columns(
        pl.col(label_col).cast(pl.Utf8).alias(LABEL_ORIGINAL_COL),
        label_groups_expr(label_col, groups).alias(label_col),
    )
