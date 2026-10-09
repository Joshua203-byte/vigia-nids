"""Correcciones automáticas (sección 8.7).

Cada corrección recibe un `AuditContext` y devuelve un `FixResult` con el
DataFrame corregido y el registro de lo que hizo. Tres reglas que valen para
todas:

1. **No modifican nada en el lugar.** Devuelven un DataFrame nuevo; el original
   queda intacto por si la corrección resultó equivocada.
2. **Nunca borran filas dudosas.** `quarantine_noise` las aparta para revisión
   humana; el juicio sobre una etiqueta sospechosa es de una persona.
3. **Dejan constancia.** El `FixResult` dice qué cambió y cuánto, y eso va al
   reporte: un dataset corregido sin registro de qué se le hizo no es
   reproducible.
"""

from __future__ import annotations

from vigia.fixes.base import FixResult, apply_fix, available_fixes, register_fix
from vigia.fixes.dataset import (
    drop_constant,
    drop_duplicates,
    drop_identifiers,
    normalize_labels,
    quarantine_noise,
    strip_column_names,
)
from vigia.fixes.splits import group_split, temporal_split

__all__ = [
    "FixResult",
    "apply_fix",
    "available_fixes",
    "drop_constant",
    "drop_duplicates",
    "drop_identifiers",
    "group_split",
    "normalize_labels",
    "quarantine_noise",
    "register_fix",
    "strip_column_names",
    "temporal_split",
]
