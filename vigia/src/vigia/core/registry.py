"""Registro de checks: cada verificación es un plugin (principio 3, sección 7.2)."""

from __future__ import annotations

from typing import Literal, Protocol, TypeVar, cast, runtime_checkable

from vigia.core.context import AuditContext
from vigia.core.findings import Finding

#: A qué módulo pertenece un check. `vigia audit` corre solo los del auditor:
#: los de envenenamiento y deriva necesitan cosas que una auditoría normal no
#: tiene (un modelo entrenado, un dataset de referencia), así que mezclarlos
#: llenaría el reporte de checks saltados por motivos que no son del dataset.
Module = Literal["auditor", "poison", "drift"]


@runtime_checkable
class Check(Protocol):
    """Interfaz común de un check (sección 7.4)."""

    id: str
    name: str
    category: str
    applies_to: set[str]

    def run(self, ctx: AuditContext) -> list[Finding]: ...


def module_of(check: Check) -> Module:
    """Módulo al que pertenece un check; 'auditor' si no lo declara."""
    return cast("Module", getattr(check, "module", "auditor"))


def emitted_ids(check: Check) -> tuple[str, ...]:
    """Ids de hallazgo que ``check`` puede emitir, incluyendo los secundarios.

    Un check puede reportar bajo más de un id: ``dup.exact`` emite además
    ``dup.class_ratio``. Quien lea ese id en el reporte tiene que poder pedirlo
    por ``--checks``, así que se declaran con el atributo ``also_emits``.
    """
    return (check.id, *getattr(check, "also_emits", ()))


C = TypeVar("C", bound=type[Check])

_REGISTRY: dict[str, Check] = {}


def register(check: C) -> C:
    """Registra un check y devuelve la clase sin modificar.

    Se usa como decorador sobre la clase; el registro guarda una instancia,
    porque los checks no llevan estado entre ejecuciones.
    """
    instance = check()
    if instance.id in _REGISTRY:
        raise ValueError(f"check duplicado: {instance.id!r}")
    _REGISTRY[instance.id] = instance
    return check


def get(check_id: str) -> Check:
    if check_id not in _REGISTRY:
        raise KeyError(f"check desconocido: {check_id!r}")
    return _REGISTRY[check_id]


def all_checks(module: Module | None = "auditor") -> list[Check]:
    """Checks registrados, ordenados por id.

    Por defecto solo los del auditor. ``module=None`` devuelve todos, sin
    importar a qué módulo pertenezcan.
    """
    _load_builtin()
    out = [_REGISTRY[k] for k in sorted(_REGISTRY)]
    if module is None:
        return out
    return [c for c in out if module_of(c) == module]


def select(spec: str | None, module: Module | None = "auditor") -> list[Check]:
    """Resuelve una selección de checks dentro de un módulo.

    ``spec`` puede ser ``None``/``"all"`` (todos), una lista separada por comas
    de ids exactos, o de prefijos de categoría (``"leak"`` toma ``leak.*``).
    """
    checks = all_checks(module)
    if spec is None or spec.strip().lower() == "all":
        return checks

    wanted = [s.strip() for s in spec.split(",") if s.strip()]
    selected: list[Check] = []
    for token in wanted:
        matches = [
            c
            for c in checks
            if any(i == token or i.startswith(f"{token}.") for i in emitted_ids(c))
        ]
        if not matches:
            known = ", ".join(i for c in checks for i in emitted_ids(c))
            raise KeyError(f"check desconocido: {token!r}. Disponibles: {known}")
        selected.extend(m for m in matches if m not in selected)
    return selected


def _load_builtin() -> None:
    """Importa los módulos de checks para que se auto-registren."""
    from vigia import (
        checks,  # noqa: F401  (el import dispara el registro)
        drift,  # noqa: F401
        poison,  # noqa: F401
    )
