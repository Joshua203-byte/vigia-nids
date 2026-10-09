"""Infraestructura de las correcciones: resultado, registro y aplicación."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import polars as pl

from vigia.core.context import AuditContext


class FixNotApplicable(Exception):
    """La corrección no puede aplicarse a este dataset (falta una columna, etc.)."""


@dataclass
class FixResult:
    """Lo que hizo una corrección, para que quede registrado en el reporte.

    Sin este registro un dataset corregido no es reproducible: nadie puede
    saber después qué se le quitó ni por qué.
    """

    fix_id: str
    df: pl.DataFrame
    rows_before: int
    rows_after: int
    cols_before: int
    cols_after: int
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    #: Filas apartadas para revisión humana, nunca borradas en silencio.
    quarantined: pl.DataFrame | None = None

    @property
    def rows_removed(self) -> int:
        return self.rows_before - self.rows_after

    @property
    def cols_removed(self) -> int:
        return self.cols_before - self.cols_after

    def to_dict(self) -> dict[str, Any]:
        return {
            "fix_id": self.fix_id,
            "rows_before": self.rows_before,
            "rows_after": self.rows_after,
            "rows_removed": self.rows_removed,
            "cols_before": self.cols_before,
            "cols_after": self.cols_after,
            "cols_removed": self.cols_removed,
            "summary": self.summary,
            "details": self.details,
            "quarantined_rows": 0 if self.quarantined is None else self.quarantined.height,
        }


Fix = Callable[[AuditContext], FixResult]

_FIXES: dict[str, Fix] = {}


def register_fix(fix_id: str) -> Callable[[Fix], Fix]:
    """Registra una corrección bajo el id que los hallazgos nombran en `auto_fix`."""

    def decorator(fn: Fix) -> Fix:
        if fix_id in _FIXES:
            raise ValueError(f"corrección duplicada: {fix_id!r}")
        _FIXES[fix_id] = fn
        return fn

    return decorator


def available_fixes() -> list[str]:
    return sorted(_FIXES)


def get_fix(fix_id: str) -> Fix:
    if fix_id not in _FIXES:
        raise KeyError(f"corrección desconocida: {fix_id!r}. Disponibles: {available_fixes()}")
    return _FIXES[fix_id]


def apply_fix(ctx: AuditContext, fix_id: str) -> FixResult:
    """Aplica una corrección y devuelve su resultado."""
    return get_fix(fix_id)(ctx)


def _result(
    ctx: AuditContext,
    fix_id: str,
    df: pl.DataFrame,
    summary: str,
    details: dict[str, Any] | None = None,
    quarantined: pl.DataFrame | None = None,
) -> FixResult:
    """Arma un FixResult midiendo el antes y el después."""
    return FixResult(
        fix_id=fix_id,
        df=df,
        rows_before=ctx.n_rows,
        rows_after=df.height,
        cols_before=ctx.n_cols,
        cols_after=df.width,
        summary=summary,
        details=details or {},
        quarantined=quarantined,
    )
