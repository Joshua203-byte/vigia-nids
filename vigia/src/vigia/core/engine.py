"""Motor de auditoría: ejecuta los checks y arma el reporte (sección 7.3)."""

from __future__ import annotations

import logging

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding, Report
from vigia.core.registry import Module, select

log = logging.getLogger(__name__)


def run_audit(
    ctx: AuditContext,
    checks: str | None = "all",
    version: str | None = None,
    module: Module | None = "auditor",
) -> Report:
    """Ejecuta los checks seleccionados sobre ``ctx`` y devuelve el reporte.

    Un check que no puede correr (``CheckSkipped``: falta una columna) va a
    ``report.skipped``. Uno que lanza cualquier otra excepción tiene un bug: va
    a ``report.errors``, aparte, para que no se lea como "no aplicaba". En los
    dos casos el resto de los checks sigue corriendo.

    ``module`` limita qué familia de checks corre. Por defecto solo la del
    auditor: los de envenenamiento y deriva necesitan cosas que una auditoría
    normal no tiene, y correrlos acá solo llenaría el reporte de checks
    saltados por motivos que no dicen nada sobre el dataset.

    ``version`` es la que queda registrada en el reporte; por defecto, la del
    paquete. Antes el default era un "0.1.0" fijo y quien llamaba a
    `run_audit(ctx, module="poison")` como enseña USO.md obtenía un reporte
    que decía 0.1.0 (AUDITORIA-1.0.md, COR-15). El import es diferido porque
    `vigia/__init__.py` importa este módulo.
    """
    if version is None:
        from vigia import __version__

        version = __version__

    report = Report(
        dataset_path=ctx.path,
        dataset_sha256=ctx.sha256,
        n_rows=ctx.n_rows,
        n_cols=ctx.n_cols,
        vigia_version=version,
        seed=ctx.seed,
    )

    for check in select(checks, module):
        try:
            found: list[Finding] = check.run(ctx)
        except CheckSkipped as exc:
            report.skipped[check.id] = str(exc)
            continue
        except Exception as exc:  # el check tiene un bug: lo aislamos
            log.exception("el check %s falló", check.id)
            report.errors[check.id] = f"{type(exc).__name__}: {exc}"
            continue
        report.findings.extend(found)

    return report
