"""Todo el código fuente tiene que poder mostrarse en una consola cp1252."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_todo_el_texto_es_cp1252():
    """La consola de Windows usa cp1252: un carácter fuera de ella hace
    fallar el comando después de haber hecho todo el trabajo."""
    raiz = Path(__file__).resolve().parents[2] / "src"
    for p in raiz.rglob("*.py"):
        for i, linea in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            try:
                linea.encode("cp1252")
            except UnicodeEncodeError:
                pytest.fail(f"{p}:{i} tiene caracteres fuera de cp1252")
