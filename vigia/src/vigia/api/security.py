"""Autenticacion, limite de peticiones y validacion de subidas (docs/PLAN.md, 2.4).

Autenticacion: clave de API en la cabecera ``X-API-Key``, comparada contra la
variable de entorno ``VIGIA_API_KEY``. Si esa variable no esta seteada, la API
corre sin autenticacion pero se loguea un warning al arrancar (ver
``vigia.api.app``): friccion cero en desarrollo, pero nunca en silencio.

Limite de peticiones: un contador en memoria por IP del cliente sobre los
endpoints que lanzan trabajos y sobre la subida. No hace falta Redis para una
sola instancia en proceso.
"""

from __future__ import annotations

import hmac
import os
from threading import Lock

from fastapi import Header, HTTPException, Request, status

from vigia.api import clock
from vigia.api.config import DEFAULT_RATE_LIMIT_PER_MINUTE, load_settings, rate_limit_per_minute

#: Formatos de dataset que la API acepta. Zeek, Suricata y PCAP quedan fuera
#: del alcance de la API (ver docstring del modulo `routes`): ya los cubre la
#: CLI, y PCAP en particular requiere aislamiento que no vale la pena montar
#: para v1 (docs/PLAN.md, 2.4.4).
VALID_EXTENSIONS = (".csv", ".parquet", ".pq")


def max_upload_bytes() -> int:
    """Limite de subida, en bytes (ver ``vigia.api.config``)."""
    return load_settings().max_upload_bytes


def configured_api_key() -> str | None:
    return os.environ.get("VIGIA_API_KEY") or None


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Dependencia de FastAPI: exige la cabecera cuando hay una clave configurada.

    Sin ``VIGIA_API_KEY`` seteada, la API queda abierta (ver el warning al
    arrancar en ``vigia.api.app``). Con la variable seteada, una clave ausente
    o incorrecta es 401.
    """
    expected = configured_api_key()
    if expected is None:
        return
    # compare_digest tarda lo mismo sin importar en que caracter difieren: con
    # `!=` el tiempo de respuesta filtra cuanto del prefijo es correcto. Por
    # red el ruido lo vuelve casi inexplotable, pero cerrarlo cuesta nada.
    if x_api_key is None or not hmac.compare_digest(
        x_api_key.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="clave de API invalida o ausente"
        )


#: Tope de identidades que el limitador recuerda a la vez. Con 10.000 entradas
#: de unos pocos cientos de bytes son pocos MB; al pasarse se olvida a las que
#: hace mas tiempo no piden nada (AUDITORIA-1.0.md, SEC-03).
MAX_RATE_IDENTITIES = 10_000

_WINDOW_SECONDS = 60.0


class RateLimiter:
    """Ventana deslizante simple en memoria: N peticiones por minuto por cliente.

    No sobrevive un reinicio ni se comparte entre procesos, que es exactamente
    lo que docs/PLAN.md pide para v1: nada de Redis.

    La memoria esta acotada: las identidades sin peticiones dentro de la
    ventana se borran, y nunca hay mas de ``MAX_RATE_IDENTITIES``.
    """

    def __init__(self, limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE) -> None:
        self.limit_per_minute = limit_per_minute
        # Orden de insercion = orden de ultimo uso: cada peticion reinserta su
        # identidad al final, asi que la primera es la que hace mas que no pide.
        self._hits: dict[str, list[float]] = {}
        self._last_prune = clock.now()
        self._lock = Lock()

    def check(self, identity: str) -> None:
        limit = rate_limit_per_minute()
        now = clock.now()
        window_start = now - _WINDOW_SECONDS
        with self._lock:
            if now - self._last_prune > _WINDOW_SECONDS:
                self._prune(window_start)
                self._last_prune = now
            hits = [t for t in self._hits.pop(identity, []) if t >= window_start]
            if len(hits) >= limit:
                self._hits[identity] = hits
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"limite de {limit} peticiones por minuto excedido",
                )
            hits.append(now)
            self._hits[identity] = hits
            while len(self._hits) > MAX_RATE_IDENTITIES:
                del self._hits[next(iter(self._hits))]

    def _prune(self, window_start: float) -> None:
        for identity in [i for i, h in self._hits.items() if not h or h[-1] < window_start]:
            del self._hits[identity]


_rate_limiter = RateLimiter()


def client_identity(request: Request) -> str:
    """Identidad del cliente para el limitador: su direccion IP.

    **Nunca** el valor de la cabecera ``X-API-Key``: la manda el cliente, asi
    que rotarla daba un contador nuevo en cada peticion y el limite no
    limitaba (AUDITORIA-1.0.md, SEC-03). Detras de un proxy la IP real llega en
    ``X-Forwarded-For``, y uvicorn solo la usa si se lo pide con
    ``--proxy-headers --forwarded-allow-ips`` apuntando al proxy: asi nadie
    puede inventarse una IP mandando la cabecera por su cuenta.
    """
    return request.client.host if request.client else "desconocido"


def enforce_rate_limit(request: Request) -> None:
    """Dependencia de FastAPI para los endpoints que lanzan trabajos pesados."""
    _rate_limiter.check(client_identity(request))


def reset_rate_limiter() -> None:
    """Limpia los contadores del limitador global. Uso exclusivo de tests, para
    que un test no herede peticiones contadas por el anterior."""
    _rate_limiter._hits.clear()


def validate_extension(filename: str | None) -> str:
    """Valida la extension del archivo subido; devuelve la extension en minusculas.

    No confiar en el nombre para el contenido (eso lo valida quien lee el
    archivo con polars), pero la extension si sirve para rechazar rapido
    formatos fuera de alcance.
    """
    if not filename or "." not in filename:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"archivo sin extension reconocible. Validas: {', '.join(VALID_EXTENSIONS)}",
        )
    suffix = "." + filename.rsplit(".", 1)[-1].lower()
    if suffix not in VALID_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"extension no soportada: {suffix!r}. Validas: {', '.join(VALID_EXTENSIONS)}",
        )
    return suffix
