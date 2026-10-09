"""Limite de tamano del cuerpo de las peticiones, aplicado antes de leerlo.

Antes el limite de subida vivia en ``save_upload``, pero para cuando la ruta lo
ejecuta Starlette ya leyo el formulario entero y lo volco a un archivo
temporal: el tope no protegia el disco ni el tiempo de nadie, y un cliente
podia mandar gigabytes sin ``Content-Length`` (AUDITORIA-1.0.md, SEC-05). Este
middleware ASGI, sin dependencias, corta en dos momentos:

* por el ``Content-Length`` declarado, sin leer ni un byte;
* contando lo que llega, para los cuerpos sin ``Content-Length``
  (``Transfer-Encoding: chunked``) o con uno mentiroso.

Solo ``POST /api/v1/datasets`` puede traer un cuerpo grande; el resto de las
rutas recibe JSON chico y tiene un tope de ``MAX_JSON_BODY_BYTES``. En
produccion el limite real tambien va en el proxy (``Caddyfile``): esto es la
defensa de quien corre la imagen sin proxy.
"""

from __future__ import annotations

from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vigia.api.config import load_settings

UPLOAD_PATH = "/api/v1/datasets"

#: Los cuerpos JSON de la API (ids y nombres de columnas) miden unos cientos de
#: bytes; 64 KiB sobra y no deja usar `/audits` para subir basura.
MAX_JSON_BODY_BYTES = 64 * 1024

#: El cuerpo multipart pesa un poco mas que el archivo (fronteras y cabeceras
#: de cada parte). El tope exacto del archivo lo sigue aplicando `save_upload`.
MULTIPART_OVERHEAD_BYTES = 64 * 1024


class _BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        limit = self._limit_for(scope["path"])
        declared = self._content_length(scope)
        if declared is not None and declared > limit:
            await self._reject(scope, receive, send, limit)
            return

        received = 0
        exceeded = False
        answered = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def filtering_send(message: Message) -> None:
            # FastAPI atrapa cualquier excepcion al leer el formulario y la
            # convierte en un 400: si nos pasamos del limite, la respuesta de
            # la app se descarta y sale un 413 en su lugar.
            nonlocal answered
            if not exceeded:
                await send(message)
            elif not answered:
                answered = True
                await self._reject(scope, receive, send, limit)

        try:
            await self.app(scope, counting_receive, filtering_send)
        except _BodyTooLarge:
            if not answered:
                await self._reject(scope, receive, send, limit)

    @staticmethod
    def _limit_for(path: str) -> int:
        if path == UPLOAD_PATH:
            return load_settings().max_upload_bytes + MULTIPART_OVERHEAD_BYTES
        return MAX_JSON_BODY_BYTES

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, limit: int) -> None:
        body: dict[str, Any] = {
            "detail": f"el cuerpo de la peticion supera el limite de {limit} bytes"
        }
        await JSONResponse(body, status_code=413)(scope, receive, send)
