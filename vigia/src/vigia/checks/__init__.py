"""Checks de Vigía. Importar este paquete registra todos los checks integrados."""

from vigia.checks import (  # noqa: F401
    duplicates,
    label_noise,
    labels,
    leakage,
    shortcuts,
    validity,
)

__all__ = ["duplicates", "label_noise", "labels", "leakage", "shortcuts", "validity"]
