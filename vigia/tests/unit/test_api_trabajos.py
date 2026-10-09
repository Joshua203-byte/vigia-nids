"""Tope de trabajos simultaneos, cola y caducidad de reportes (docs/PLAN.md, "Despliegue").

Una auditoria de 1 M x 80 pica a 5,4 GiB: en un servidor de 8 GB, dos a la
vez pueden matar el proceso por falta de memoria. Y sin caducidad, los
reportes (con sus resultados) se acumulaban en memoria para siempre.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from vigia.api import clock, jobs, routes, storage
from vigia.api.app import app
from vigia.api.jobs import store
from vigia.api.security import reset_rate_limiter

CSV = b"x,y,label\n" + b"\n".join(
    f"{i},{i * 2},{'a' if i % 2 else 'b'}".encode() for i in range(40)
)


class Reloj:
    def __init__(self) -> None:
        # Chico a proposito: no tiene que depender del tiempo que lleve encendida la
        # maquina (VERIFICACION-1.0.md, VER-02).
        self.t = 10.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _limpio(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    reset_rate_limiter()
    jobs.reset_scheduler()
    monkeypatch.setenv("VIGIA_RATE_LIMIT_PER_MINUTE", "1000")
    yield
    jobs.reset_scheduler()


@pytest.fixture
def reloj(monkeypatch: pytest.MonkeyPatch) -> Reloj:
    r = Reloj()
    monkeypatch.setattr(clock, "now", r)
    return r


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


class Compuerta:
    """Reemplaza el trabajo de auditoria por uno que espera una senal, para
    controlar cuantos corren a la vez sin dormir."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.abierta = threading.Event()
        self.corriendo = 0
        self.maximo = 0
        self._lock = threading.Lock()
        original = routes._audit_work

        def trabajo(req):  # type: ignore[no-untyped-def]
            with self._lock:
                self.corriendo += 1
                self.maximo = max(self.maximo, self.corriendo)
            try:
                assert self.abierta.wait(10)
                return original(req)
            finally:
                with self._lock:
                    self.corriendo -= 1

        monkeypatch.setattr(routes, "_audit_work", trabajo)


def _subir(client: TestClient) -> str:
    r = client.post("/api/v1/datasets", files={"file": ("f.csv", CSV, "text/csv")})
    assert r.status_code == 201, r.text
    return r.json()["dataset_id"]


def _auditar(client: TestClient, dataset_id: str):  # type: ignore[no-untyped-def]
    return client.post("/api/v1/audits", json={"dataset_id": dataset_id, "label_col": "label"})


def _estado(client: TestClient, job_id: str) -> str:
    return client.get(f"/api/v1/audits/{job_id}").json()["status"]


def _esperar(client: TestClient, job_id: str, estado: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _estado(client, job_id) == estado:
            return
        time.sleep(0.02)
    raise TimeoutError(f"{job_id} no llego a {estado}")


def test_el_tope_de_trabajos_se_respeta_y_el_resto_espera_en_la_cola(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_MAX_CONCURRENT_JOBS", "1")
    monkeypatch.setenv("VIGIA_MAX_QUEUED_JOBS", "1")
    compuerta = Compuerta(monkeypatch)
    a, b = (_subir(client) for _ in range(2))

    ra, rb = _auditar(client, a), _auditar(client, b)
    assert ra.status_code == rb.status_code == 202
    _esperar(client, ra.json()["job_id"], "corriendo")
    assert _estado(client, rb.json()["job_id"]) == "pendiente"

    compuerta.abierta.set()
    _esperar(client, ra.json()["job_id"], "terminado")
    _esperar(client, rb.json()["job_id"], "terminado")
    assert compuerta.maximo == 1


def test_con_la_cola_llena_responde_503_con_retry_after_y_no_gasta_el_dataset(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_MAX_CONCURRENT_JOBS", "1")
    monkeypatch.setenv("VIGIA_MAX_QUEUED_JOBS", "1")
    compuerta = Compuerta(monkeypatch)
    a, b, c = (_subir(client) for _ in range(3))
    _auditar(client, a)
    _auditar(client, b)

    r = _auditar(client, c)
    assert r.status_code == 503
    assert int(r.headers["Retry-After"]) > 0
    # El rechazo no consumio el dataset: el cliente puede reintentar con el mismo id.
    assert any(c in p.name for p in storage.storage_dir().iterdir())

    compuerta.abierta.set()
    storage.delete_dataset(c)


def test_un_dataset_en_la_cola_no_caduca_por_ttl_de_subida(
    client: TestClient, reloj: Reloj, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_MAX_CONCURRENT_JOBS", "1")
    monkeypatch.setenv("VIGIA_MAX_QUEUED_JOBS", "2")
    monkeypatch.setenv("VIGIA_UPLOAD_TTL_MINUTES", "1")
    compuerta = Compuerta(monkeypatch)
    a, b = (_subir(client) for _ in range(2))
    ra, rb = _auditar(client, a), _auditar(client, b)

    reloj.t += 3600
    assert b not in storage.purge_expired_uploads()
    assert any(b in p.name for p in storage.storage_dir().iterdir())

    compuerta.abierta.set()
    _esperar(client, ra.json()["job_id"], "terminado")
    _esperar(client, rb.json()["job_id"], "terminado")


def test_un_reporte_terminado_caduca_y_el_get_lo_dice(
    client: TestClient, reloj: Reloj, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_REPORT_TTL_MINUTES", "10")
    r = _auditar(client, _subir(client))
    job_id = r.json()["job_id"]
    _esperar(client, job_id, "terminado")

    reloj.t += 9 * 60
    store().purge_expired()
    assert client.get(f"/api/v1/audits/{job_id}").status_code == 200

    reloj.t += 2 * 60
    store().purge_expired()
    caducado = client.get(f"/api/v1/audits/{job_id}")
    assert caducado.status_code == 410
    assert "caduc" in caducado.json()["detail"]
    assert client.get(f"/api/v1/audits/{job_id}/report.html").status_code == 410
    # Un id que nunca existio sigue siendo 404.
    assert client.get(f"/api/v1/audits/{'0' * 32}").status_code == 404


def test_hay_un_tope_de_trabajos_guardados_en_memoria(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_MAX_STORED_JOBS", "2")
    ids = []
    for _ in range(3):
        job_id = _auditar(client, _subir(client)).json()["job_id"]
        _esperar(client, job_id, "terminado")
        ids.append(job_id)
    assert client.get(f"/api/v1/audits/{ids[0]}").status_code == 410  # el mas viejo
    assert client.get(f"/api/v1/audits/{ids[2]}").status_code == 200
