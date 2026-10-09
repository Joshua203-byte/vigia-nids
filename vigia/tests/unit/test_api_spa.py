"""El panel se sirve desde la API con fallback de SPA (AUDITORIA-1.0.md, COR-09).

React Router resuelve `/resultado/<id>` en el navegador, pero al recargar esa
URL el pedido llega al servidor, que no tiene ese archivo: antes daba 404 y
los enlaces profundos del panel no sobrevivian a un F5.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from vigia.api.app import mount_web
from vigia.api.routes import health_router, router


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html><body>PANEL</body></html>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('hola')", encoding="utf-8")
    app = FastAPI()
    app.include_router(health_router)
    app.include_router(router, prefix="/api/v1")
    mount_web(app, dist)
    return TestClient(app)


def test_un_enlace_profundo_del_panel_devuelve_el_index(client: TestClient) -> None:
    r = client.get("/resultado/abc")
    assert r.status_code == 200
    assert "PANEL" in r.text
    assert "text/html" in r.headers["content-type"]


def test_la_raiz_y_los_archivos_estaticos_siguen_funcionando(client: TestClient) -> None:
    assert "PANEL" in client.get("/").text
    r = client.get("/assets/app.js")
    assert r.status_code == 200 and "hola" in r.text


def test_un_archivo_estatico_que_no_existe_sigue_siendo_404_para_la_api(
    client: TestClient,
) -> None:
    r = client.get("/api/v1/no-existe")
    assert r.status_code == 404
    assert "PANEL" not in r.text
    assert r.json()["detail"] == "Not Found"


def test_health_no_lo_pisa_el_fallback(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}
