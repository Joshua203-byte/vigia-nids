"""API REST de Vigia (docs/PLAN.md, fase 2): entrypoint FastAPI.

Levantar el servidor:

    uvicorn vigia.api.app:app --host 0.0.0.0 --port 8000

o, si se instalo el extra ``api``, con el comando ``vigia serve``.

Autenticacion: clave en la cabecera ``X-API-Key``, comparada contra la
variable de entorno ``VIGIA_API_KEY``. **Decision de diseno:** si esa
variable no esta seteada, la API corre sin autenticacion en vez de
rechazar todo. Se prioriza que sea usable en desarrollo local sin friccion
(subir un CSV y probar un endpoint no deberia requerir configurar una clave
primero), a costa de que "abierta por defecto" sea mas facil de dejar pasar
por error en produccion. Para mitigarlo, arrancar sin la variable emite un
warning explicito en el log (ver `_warn_if_unauthenticated`), no un silencio.
Con ``VIGIA_ENV=production`` (que setea el compose de produccion) el default
es el inverso: sin ``VIGIA_API_KEY`` el arranque falla (`vigia.api.config`,
AUDITORIA-1.0.md, SEC-09), asi la imagen de produccion nunca queda abierta
en silencio.

Limite de peticiones: en memoria, por clave de API o IP, solo sobre los
endpoints que lanzan trabajos (`/audits`, `/poison`, `/drift`). Ver
`vigia.api.security.RateLimiter`.

Nunca se usa pickle: el estado de los trabajos vive en un diccionario en
memoria (`vigia.api.jobs`) y lo que sale por HTTP es JSON via Pydantic.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.types import Scope

from vigia.api.config import load_settings, memory_warning
from vigia.api.jobs import store
from vigia.api.middleware import BodyLimitMiddleware
from vigia.api.routes import health_router, router
from vigia.api.security import configured_api_key
from vigia.api.storage import purge_expired_uploads

log = logging.getLogger("vigia.api")

JANITOR_INTERVAL_SECONDS = 60.0


async def _janitor() -> None:
    """Tarea periodica de limpieza: no hace falta mas precision que un minuto
    para un TTL medido en minutos."""
    while True:
        await asyncio.sleep(JANITOR_INTERVAL_SECONDS)
        try:
            purge_expired_uploads()
            store().purge_expired()
        except Exception:
            log.exception("fallo la limpieza periodica")


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = load_settings()  # falla aca, no en la primera peticion, si el entorno esta mal
    if configured_api_key() is None:
        log.warning(
            "VIGIA_API_KEY no esta seteada: la API corre SIN autenticacion. "
            "Cualquiera que llegue a este puerto puede subir datasets y lanzar "
            "trabajos. Setear VIGIA_API_KEY antes de exponerla fuera de una "
            "maquina de desarrollo."
        )
    log.info("limite de subida: %s MB", settings.max_upload_mb)
    aviso = memory_warning(settings)
    if aviso:
        log.warning(aviso)
    # Las subidas que ningun trabajo usa se borran solas (AUDITORIA-1.0.md, SEC-02).
    janitor = asyncio.create_task(_janitor())
    try:
        yield
    finally:
        janitor.cancel()


app = FastAPI(
    title="Vigia API",
    description="Control de calidad continuo para datos de modelos de deteccion de intrusiones.",
    version="1",
    lifespan=_lifespan,
)

# CORS (docs/PLAN.md, fase 3): el panel web (React + Vite) corre en un origen
# distinto al de la API durante el desarrollo (Vite por defecto en
# http://localhost:5173). Sin esto el navegador bloquea las peticiones desde
# el panel aunque la API responda bien -- no es una restriccion del servidor,
# es el navegador aplicando same-origin policy.
#
# `VIGIA_CORS_ORIGINS` permite configurar los origenes permitidos en
# produccion (lista separada por comas). Sin la variable seteada, se permite
# el dev server de Vite y `http://localhost:8000` (el mismo puerto que la API,
# para cuando el frontend se sirve como estatico desde este mismo proceso).
# Un "*" hace fallar el arranque (vigia.api.config).
#
# El middleware de limite de cuerpo se agrega antes que CORS para que CORS
# quede por fuera y el 413 lleve sus cabeceras.
app.add_middleware(BodyLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(load_settings().cors_origins),
    # La clave viaja en la cabecera X-API-Key, no en cookies: no hace falta
    # permitir credenciales (AUDITORIA-1.0.md, SEC-12).
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(router, prefix="/api/v1")


class SPAStaticFiles(StaticFiles):
    """Archivos estaticos con fallback de aplicacion de una sola pagina.

    React Router resuelve ``/resultado/<id>`` en el navegador, pero al recargar
    esa URL el pedido llega aca y no hay un archivo con ese nombre: antes daba
    404 (AUDITORIA-1.0.md, COR-09). Una ruta que no es un archivo y no es de la
    API devuelve ``index.html``; ``/api`` y ``/health`` siguen dando su 404.
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            # StaticFiles normaliza la ruta con el separador del sistema: en
            # Windows llega como "api\v1\x".
            primero = path.replace("\\", "/").split("/", 1)[0]
            if exc.status_code != 404 or primero in ("api", "health"):
                raise
            return await super().get_response("index.html", scope)


def mount_web(app: FastAPI, dist: Path) -> None:
    """Sirve el build del panel desde este mismo proceso."""
    app.mount("/", SPAStaticFiles(directory=str(dist), html=True), name="web")


# Panel web estatico (docs/PLAN.md, fase 3.5): en Docker, el build de
# `web/dist` se copia junto al paquete y se sirve desde este mismo proceso,
# para que `docker compose up` deje todo navegable en un solo puerto sin un
# proxy aparte. `VIGIA_WEB_DIST` permite apuntar a otra ubicacion; si no
# existe (por ejemplo, corriendo la API sola en desarrollo con `npm run dev`
# aparte, o durante los tests), no se monta nada y la API sigue funcionando
# igual -- esto es opcional, no un requisito para que la API arranque.
_web_dist = Path(os.environ.get("VIGIA_WEB_DIST", "web/dist"))
if _web_dist.is_dir():
    mount_web(app, _web_dist)
