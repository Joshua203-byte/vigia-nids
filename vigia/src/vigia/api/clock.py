"""Reloj monotonico de la API, en un solo lugar para poder reemplazarlo.

Los TTL de subidas y de reportes dependen del tiempo. Todos los modulos de la
API llaman a ``clock.now()`` (siempre por el modulo, no ``from ... import
now``): los tests lo reemplazan con ``monkeypatch.setattr`` y avanzan el
tiempo sin dormir.
"""

from __future__ import annotations

import time


def now() -> float:
    return time.monotonic()
