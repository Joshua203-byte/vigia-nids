"""Limitador de peticiones: identidad y memoria acotadas (AUDITORIA-1.0.md, SEC-03).

La identidad era el valor crudo de ``X-API-Key``: con la API abierta, o con un
cliente que tiene la clave, rotar la cabecera daba un contador nuevo cada vez
y el limite no limitaba. Y ``_hits`` guardaba una entrada por identidad para
siempre: mandar claves distintas era una fuga de memoria.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from vigia.api import clock
from vigia.api.app import app
from vigia.api.security import MAX_RATE_IDENTITIES, RateLimiter, reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    reset_rate_limiter()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def test_rotar_la_cabecera_x_api_key_no_evade_el_limite(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_RATE_LIMIT_PER_MINUTE", "2")
    cuerpo = {"dataset_id": "0" * 32}
    codigos = [
        client.post("/api/v1/audits", json=cuerpo, headers={"X-API-Key": f"clave-{i}"}).status_code
        for i in range(4)
    ]
    assert 429 in codigos


def test_con_clave_configurada_el_limite_tambien_es_por_cliente(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_API_KEY", "la-clave")
    monkeypatch.setenv("VIGIA_RATE_LIMIT_PER_MINUTE", "2")
    cuerpo = {"dataset_id": "0" * 32}
    codigos = [
        client.post("/api/v1/audits", json=cuerpo, headers={"X-API-Key": "la-clave"}).status_code
        for _ in range(4)
    ]
    assert codigos[:2] == [404, 404] and codigos[2:] == [429, 429]


def test_las_identidades_sin_peticiones_en_la_ventana_se_borran(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    t = [1000.0]
    monkeypatch.setattr(clock, "now", lambda: t[0])
    limitador = RateLimiter(limit_per_minute=5)
    for i in range(10_000):
        limitador.check(f"10.0.{i // 256}.{i % 256}")
    t[0] += 3600  # todas las ventanas quedaron en el pasado
    limitador.check("10.99.99.99")
    assert len(limitador._hits) == 1


def test_hay_un_tope_de_identidades_aun_dentro_de_la_ventana(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clock, "now", lambda: 1000.0)
    limitador = RateLimiter(limit_per_minute=5)
    for i in range(MAX_RATE_IDENTITIES + 500):
        limitador.check(f"id-{i}")
    assert len(limitador._hits) <= MAX_RATE_IDENTITIES
