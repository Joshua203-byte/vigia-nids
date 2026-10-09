"""Módulo 2 — detección de envenenamiento (sección 9 del documento maestro).

Busca registros insertados a propósito para manipular el modelo: etiquetas
cambiadas, filas fabricadas, o un patrón que funcione como puerta trasera.

Tres cosas que distinguen este módulo del auditor:

1. **El puntaje es por fila, no por columna.** Un defecto de calidad afecta a
   una columna entera; un envenenamiento afecta a un puñado de filas concretas.
   Por eso los hallazgos traen `row_indices` y `row_scores`.

2. **Los detectores se combinan.** Ninguno por sí solo distingue bien el
   envenenamiento del ruido natural. `combine_scores` promedia el puntaje de
   varios sobre la misma fila.

3. **No hay datos reales de envenenamiento.** Por eso el módulo incluye un
   simulador: se inyecta envenenamiento controlado sobre un dataset limpio y se
   mide qué fracción encuentra cada detector. Sin eso, un detector que no
   encuentra nada y uno que funciona se ven igual.
"""

from __future__ import annotations

from vigia.poison import detectors  # noqa: F401  (el import dispara el registro)
from vigia.poison.combine import Suspect, combine_scores, rank_suspects
from vigia.poison.simulate import (
    PoisonSpec,
    inject_backdoor,
    inject_label_flip,
    inject_synthetic,
)

__all__ = [
    "PoisonSpec",
    "Suspect",
    "combine_scores",
    "inject_backdoor",
    "inject_label_flip",
    "inject_synthetic",
    "detectors",
    "rank_suspects",
]
