"""Errores internos hacia el cliente: mensaje generico y un id de correlacion.

El mensaje de una excepcion de Polars puede traer fragmentos de filas del
dataset o rutas del servidor, y la API lo devolvia tal cual (AUDITORIA-1.0.md,
SEC-06). Ahora el cliente recibe el tipo de error (o una frase generica) y un
id; el detalle completo, con el traceback, queda en el log con ese mismo id:
quien administra el servidor lo busca ahi. En la CLI local el detalle sigue
yendo a la pantalla: ahi el usuario es el dueno de los datos.
"""

from __future__ import annotations

import logging
import uuid

log = logging.getLogger("vigia.api")


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:12]


def log_exception(context: str, exc: BaseException) -> str:
    """Registra ``exc`` con su traceback y devuelve el id de correlacion."""
    correlation_id = new_correlation_id()
    log.error("%s (id: %s)", context, correlation_id, exc_info=exc)
    return correlation_id


def log_detail(context: str, detail: str) -> str:
    """Igual que ``log_exception`` para cuando solo hay un texto (los errores de
    los checks ya vienen como ``"Tipo: mensaje"``)."""
    correlation_id = new_correlation_id()
    log.error("%s (id: %s): %s", context, correlation_id, detail)
    return correlation_id
