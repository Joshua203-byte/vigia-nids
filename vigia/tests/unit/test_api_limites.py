"""Limite de cuerpo de las peticiones (AUDITORIA-1.0.md, SEC-05).

El limite de subida se aplicaba despues de que Starlette ya habia leido y
guardado el cuerpo entero (el parser de formularios lo vuelca a un archivo
temporal antes de que la ruta lo vea). Estos tests lo cortan antes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from vigia.api.app import app
from vigia.api.middleware import MAX_JSON_BODY_BYTES, BodyLimitMiddleware
from vigia.api.security import reset_rate_limiter
from vigia.api.storage import storage_dir

MB = 1024 * 1024
BOUNDARY = "frontera-de-prueba"


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    reset_rate_limiter()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("VIGIA_MAX_UPLOAD_MB", "1")
    with TestClient(app) as c:
        yield c


def _multipart(n_bytes: int) -> bytes:
    cabecera = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="x.csv"\r\n'
        "Content-Type: text/csv\r\n\r\n"
    ).encode()
    return cabecera + b"a,b\n" + b"1,2\n" * (n_bytes // 4) + f"\r\n--{BOUNDARY}--\r\n".encode()


_CT = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


def test_content_length_declarado_por_encima_del_limite_da_413(client: TestClient) -> None:
    antes = set(storage_dir().iterdir())
    r = client.post("/api/v1/datasets", content=_multipart(5 * MB), headers=_CT)
    assert r.status_code == 413
    assert set(storage_dir().iterdir()) == antes


def test_cuerpo_chunked_sin_content_length_tambien_da_413(client: TestClient) -> None:
    cuerpo = _multipart(5 * MB)

    def trozos() -> Iterator[bytes]:
        for i in range(0, len(cuerpo), 256 * 1024):
            yield cuerpo[i : i + 256 * 1024]

    antes = set(storage_dir().iterdir())
    r = client.post("/api/v1/datasets", content=trozos(), headers=_CT)
    assert r.status_code == 413
    assert set(storage_dir().iterdir()) == antes


def test_una_subida_dentro_del_limite_sigue_funcionando(client: TestClient) -> None:
    r = client.post("/api/v1/datasets", content=_multipart(200 * 1024), headers=_CT)
    assert r.status_code == 201


def test_los_cuerpos_json_tienen_un_tope_chico(client: TestClient) -> None:
    grande = '{"dataset_id": "' + "a" * (MAX_JSON_BODY_BYTES + 10) + '"}'
    r = client.post("/api/v1/audits", content=grande, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


async def _correr(
    middleware: BodyLimitMiddleware, path: str, chunks: list[bytes], headers: list[Any]
) -> tuple[list[int], int]:
    """Corre la app ASGI a mano y cuenta cuantos bytes llegaron a la app de
    adentro: es lo que el parser de formularios terminaria volcando a disco."""
    pendientes = list(chunks)
    respuestas: list[int] = []

    async def receive() -> dict[str, Any]:
        if not pendientes:
            return {"type": "http.disconnect"}
        trozo = pendientes.pop(0)
        return {"type": "http.request", "body": trozo, "more_body": bool(pendientes)}

    async def send(msg: dict[str, Any]) -> None:
        if msg["type"] == "http.response.start":
            respuestas.append(msg["status"])

    scope = {"type": "http", "method": "POST", "path": path, "headers": headers}
    await middleware(scope, receive, send)
    return respuestas, len(pendientes)


def test_el_stream_se_corta_apenas_se_supera_el_limite(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIA_MAX_UPLOAD_MB", "1")
    leidos = 0

    async def interna(scope: Any, receive: Any, send: Any) -> None:
        nonlocal leidos
        while True:
            msg = await receive()
            leidos += len(msg.get("body", b""))
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    trozos = [b"x" * (256 * 1024)] * 40  # 10 MB sin Content-Length
    respuestas, sin_leer = asyncio.run(
        _correr(BodyLimitMiddleware(interna), "/api/v1/datasets", trozos, [])
    )
    assert respuestas == [413]
    assert leidos <= 2 * MB  # el limite de 1 MB mas el margen del multipart
    assert sin_leer > 30  # casi todo el cuerpo quedo sin leer
