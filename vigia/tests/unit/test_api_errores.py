"""Los errores internos no llegan al cliente con sus detalles (AUDITORIA-1.0.md, SEC-06).

El mensaje de una excepcion de Polars puede traer fragmentos de filas o rutas
del servidor. Al cliente le llega un mensaje generico y un id de correlacion;
el detalle completo queda en el log con ese mismo id.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterator
from typing import Any

import polars as pl
import pytest
from fastapi.testclient import TestClient

from vigia.api import routes, storage
from vigia.api.app import app
from vigia.api.security import reset_rate_limiter
from vigia.checks.duplicates import ExactDuplicateCheck

SECRETO = "C:/srv/vigia/uploads/secreto.csv fila: 10.0.0.5,clave-del-cliente"
CSV = b"x,y,label\n" + b"\n".join(
    f"{i},{i * 2},{'a' if i % 2 else 'b'}".encode() for i in range(30)
)


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    reset_rate_limiter()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def _subir(client: TestClient) -> str:
    r = client.post("/api/v1/datasets", files={"file": ("f.csv", CSV, "text/csv")})
    assert r.status_code == 201
    return r.json()["dataset_id"]


def _esperar(client: TestClient, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        data = client.get(f"/api/v1/audits/{job_id}").json()
        if data["status"] in ("terminado", "fallido"):
            return data
        time.sleep(0.02)
    raise TimeoutError(job_id)


def _id_de_correlacion(texto: str) -> str:
    m = re.search(r"id: ([0-9a-f]{12})", texto)
    assert m, f"el mensaje no trae un id de correlacion: {texto!r}"
    return m.group(1)


def test_un_trabajo_que_falla_no_filtra_el_mensaje_pero_lo_deja_en_el_log(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def roto(req: Any) -> Any:
        raise RuntimeError(SECRETO)

    monkeypatch.setattr(routes, "_audit_work", roto)
    job = client.post("/api/v1/audits", json={"dataset_id": _subir(client)}).json()["job_id"]
    with caplog.at_level(logging.ERROR):
        data = _esperar(client, job)

    assert data["status"] == "fallido"
    assert "secreto" not in data["error"] and "clave-del-cliente" not in data["error"]
    correlacion = _id_de_correlacion(data["error"])
    registros = [r for r in caplog.records if correlacion in r.getMessage()]
    assert registros, "el log no tiene el id de correlacion"
    assert any(
        SECRETO in r.getMessage() or (r.exc_info and SECRETO in str(r.exc_info[1]))
        for r in registros
    )


def test_una_subida_ilegible_no_filtra_el_detalle_de_polars(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def falla(*args: Any, **kwargs: Any) -> Any:
        raise ValueError(SECRETO)

    monkeypatch.setattr(storage, "read_csv_sample", falla)
    with caplog.at_level(logging.ERROR):
        r = client.post("/api/v1/datasets", files={"file": ("f.csv", CSV, "text/csv")})
    assert r.status_code == 415
    detalle = r.json()["detail"]
    assert "secreto" not in detalle and "clave-del-cliente" not in detalle
    correlacion = _id_de_correlacion(detalle)
    assert any(correlacion in rec.getMessage() for rec in caplog.records)


def test_un_check_roto_no_filtra_su_mensaje_en_el_reporte_de_la_api(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def roto(self: Any, ctx: Any) -> Any:
        raise pl.exceptions.ComputeError(SECRETO)

    monkeypatch.setattr(ExactDuplicateCheck, "run", roto)
    job = client.post(
        "/api/v1/audits", json={"dataset_id": _subir(client), "checks": "dup.exact"}
    ).json()["job_id"]
    with caplog.at_level(logging.ERROR):
        data = _esperar(client, job)

    assert data["status"] == "terminado"
    error = data["result"]["errors"]["dup.exact"]
    assert "secreto" not in error and "clave-del-cliente" not in error
    assert error.startswith("ComputeError")  # el tipo si ayuda y no filtra nada
    correlacion = _id_de_correlacion(error)
    assert any(correlacion in rec.getMessage() for rec in caplog.records)


def _skipped_de_un_trabajo_de_deriva(client: TestClient) -> dict[str, Any]:
    import numpy as np

    rng = np.random.default_rng(0)

    def csv(n: int) -> bytes:
        x = rng.normal(size=(n, 3))
        y = np.where(x[:, 0] > 0, "a", "b")
        return (
            pl.DataFrame({"f0": x[:, 0], "f1": x[:, 1], "f2": x[:, 2], "label": y})
            .write_csv()
            .encode()
        )

    ids = [
        client.post("/api/v1/datasets", files={"file": ("f.csv", csv(400), "text/csv")}).json()[
            "dataset_id"
        ]
        for _ in range(2)
    ]
    job = client.post(
        "/api/v1/drift", json={"dataset_id": ids[0], "reference_id": ids[1], "label_col": "label"}
    ).json()["job_id"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        data = client.get(f"/api/v1/drift/{job}").json()
        if data["status"] in ("terminado", "fallido"):
            return data
        time.sleep(0.05)
    raise TimeoutError(job)


def test_un_fallo_de_entrenamiento_es_un_error_y_no_un_salto_con_el_texto_de_la_excepcion(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """`CheckSkipped(f"no se pudo entrenar ...: {exc}")` mandaba el mensaje de
    scikit-learn por la API en `skipped`, y un defecto del entrenamiento figuraba
    como "no aplica" (gris) en vez de como error (rojo) (VERIFICACION-1.0.md, VER-05)."""
    pytest.importorskip("sklearn")
    from sklearn.ensemble import RandomForestClassifier

    def roto(self: Any, *a: Any, **k: Any) -> Any:
        raise ValueError(SECRETO)

    monkeypatch.setattr(RandomForestClassifier, "fit", roto)
    with caplog.at_level(logging.ERROR):
        data = _skipped_de_un_trabajo_de_deriva(client)

    resultado = data["result"]
    assert "secreto" not in str(resultado) and "clave-del-cliente" not in str(resultado)
    for check in ("drift.concept", "drift.covariate"):
        assert check not in resultado["skipped"], resultado["skipped"]
        assert check in resultado["errors"], resultado["errors"]
    assert resultado["summary"]["traffic_light"] == "rojo"
    assert any(SECRETO in rec.getMessage() for rec in caplog.records)


def test_los_motivos_de_salto_que_salen_por_la_api_no_llevan_rutas_ni_ips() -> None:
    """Defensa en profundidad: aunque algun check meta un texto ajeno en el motivo
    de un salto, `_anonymize` lo limpia."""
    from vigia.api.routes import _anonymize
    from vigia.core.findings import Report

    r = Report("/srv/x.csv", "0", 1, 1, "1.0.0", 0)
    r.skipped = {
        "a.uno": r"no se pudo: C:\srv\vigia\uploads\secreto.csv fila 10.0.0.5",
        "a.dos": "no se pudo: /srv/vigia/uploads/secreto.csv",
        "a.tres": "falta la columna 'Label'",
        "a.cuatro": "x" * 1000,
    }
    limpio = _anonymize(r, "0" * 32).skipped
    assert "secreto" not in limpio["a.uno"] and "10.0.0.5" not in limpio["a.uno"]
    assert "secreto" not in limpio["a.dos"]
    assert limpio["a.tres"] == "falta la columna 'Label'"  # un motivo normal no se toca
    assert len(limpio["a.cuatro"]) <= 300


def test_ningun_check_mete_el_texto_de_una_excepcion_en_el_motivo_de_un_salto() -> None:
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "vigia"
    culpables = []
    for archivo in src.rglob("*.py"):
        for nodo in ast.walk(ast.parse(archivo.read_text(encoding="utf-8"))):
            if isinstance(nodo, ast.Call) and getattr(nodo.func, "id", "") == "CheckSkipped":
                nombres = {n.id for n in ast.walk(nodo) if isinstance(n, ast.Name)}
                if nombres & {"exc", "e", "err"}:
                    culpables.append(f"{archivo.name}:{nodo.lineno}")
    assert culpables == []
