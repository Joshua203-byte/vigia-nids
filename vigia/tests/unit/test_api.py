"""Tests de la API REST (docs/PLAN.md, fase 2.5).

Nota importante sobre `TestClient`: los trabajos se lanzan con
`asyncio.create_task` para no bloquear el event loop (ver `vigia.api.jobs`).
`starlette.testclient.TestClient` solo mantiene un `BlockingPortal` vivo entre
peticiones cuando se usa como *context manager* (`with TestClient(app) as
client:`); sin eso, cada petición abre y cierra su propio portal efimero y
cancela cualquier tarea en segundo plano que haya creado. Todos los tests que
lanzan un trabajo usan el context manager por eso.
"""

from __future__ import annotations

import io
import time
from collections.abc import Iterator

import polars as pl
import pytest
from fastapi.testclient import TestClient

from vigia.api.app import app
from vigia.api.security import reset_rate_limiter
from vigia.api.storage import storage_dir


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    """Evita que el contador de un test contamine al siguiente: el limitador
    es un singleton en memoria compartido por todo el proceso de test."""
    reset_rate_limiter()


def _small_csv_bytes() -> bytes:
    df = pl.DataFrame(
        {
            "duration": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0],
            "bytes_fwd": [10, 20, 30, 40, 50, 60, 70, 80],
            "label": [
                "benign",
                "attack",
                "benign",
                "attack",
                "benign",
                "attack",
                "benign",
                "attack",
            ],
            "split": ["train", "train", "train", "train", "train", "train", "test", "test"],
        }
    )
    buf = io.BytesIO()
    df.write_csv(buf)
    return buf.getvalue()


def _wait_for_job(
    client: TestClient, job_id: str, kind: str = "audits", timeout: float = 15.0
) -> dict:
    deadline = time.monotonic() + timeout
    data: dict = {}
    while time.monotonic() < deadline:
        r = client.get(f"/api/v1/{kind}/{job_id}")
        data = r.json()
        if data["status"] in ("terminado", "fallido"):
            return data
        time.sleep(0.05)
    raise TimeoutError(f"el trabajo {job_id} no termino a tiempo: {data}")


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def test_health_check() -> None:
    with TestClient(app) as c:
        r = c.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_catalogo_de_checks_no_vacio(client: TestClient) -> None:
    r = client.get("/api/v1/checks")
    assert r.status_code == 200
    body = r.json()
    assert len(body) > 0
    assert {"id", "name", "category", "module"} <= body[0].keys()


def test_flujo_feliz_completo(client: TestClient) -> None:
    r = client.post(
        "/api/v1/datasets",
        files={"file": ("flows.csv", _small_csv_bytes(), "text/csv")},
    )
    assert r.status_code == 201
    dataset_id = r.json()["dataset_id"]
    assert r.json()["n_rows"] == 8

    r = client.post(
        "/api/v1/audits",
        json={"dataset_id": dataset_id, "label_col": "label", "split_col": "split"},
    )
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    data = _wait_for_job(client, job_id)
    assert data["status"] == "terminado"
    result = data["result"]
    assert "summary" in result
    assert result["summary"]["traffic_light"] in ("rojo", "amarillo", "verde", "gris")
    assert result["dataset"]["n_rows"] == 8
    # No se filtra la ruta interna del servidor: solo el id opaco.
    assert result["dataset"]["path"] == f"dataset:{dataset_id}"
    assert str(storage_dir()) not in str(result)

    r = client.get(f"/api/v1/audits/{job_id}/report.html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert r.text.strip().lower().startswith("<!doctype html")
    assert "</html>" in r.text.lower()


def test_extension_no_soportada(client: TestClient) -> None:
    r = client.post(
        "/api/v1/datasets",
        files={"file": ("captura.pcap", b"no importa el contenido", "application/octet-stream")},
    )
    assert r.status_code == 415
    body = r.json()["detail"]
    assert ".csv" in body and ".parquet" in body


def test_archivo_mas_grande_que_el_limite(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    monkeypatch.setenv("VIGIA_MAX_UPLOAD_MB", "0")  # ~0 MB: cualquier contenido lo supera
    contenido = _small_csv_bytes()
    r = client.post(
        "/api/v1/datasets",
        files={"file": ("flows.csv", contenido, "text/csv")},
    )
    assert r.status_code == 413


def test_id_de_trabajo_inexistente(client: TestClient) -> None:
    # Un id con la forma correcta que no corresponde a ningun trabajo. Uno con
    # otra forma da 422 (ver test_job_id_con_forma_invalida_da_422).
    r = client.get(f"/api/v1/audits/{'0' * 32}")
    assert r.status_code == 404


def test_dos_trabajos_simultaneos_no_se_pisan(client: TestClient) -> None:
    df_a = pl.DataFrame(
        {
            "duration": [1.0, 2.0, 3.0, 4.0],
            "label": ["benign", "attack", "benign", "attack"],
            "split": ["train", "train", "test", "test"],
        }
    )
    df_b = pl.DataFrame(
        {
            "duration": [10.0, 20.0, 30.0, 40.0, 50.0, 60.0],
            "label": ["attack", "attack", "benign", "benign", "attack", "benign"],
            "split": ["train", "train", "train", "test", "test", "test"],
        }
    )
    buf_a, buf_b = io.BytesIO(), io.BytesIO()
    df_a.write_csv(buf_a)
    df_b.write_csv(buf_b)

    r_a = client.post("/api/v1/datasets", files={"file": ("a.csv", buf_a.getvalue(), "text/csv")})
    r_b = client.post("/api/v1/datasets", files={"file": ("b.csv", buf_b.getvalue(), "text/csv")})
    id_a, id_b = r_a.json()["dataset_id"], r_b.json()["dataset_id"]
    assert id_a != id_b

    job_a = client.post(
        "/api/v1/audits", json={"dataset_id": id_a, "label_col": "label", "split_col": "split"}
    ).json()["job_id"]
    job_b = client.post(
        "/api/v1/audits", json={"dataset_id": id_b, "label_col": "label", "split_col": "split"}
    ).json()["job_id"]
    assert job_a != job_b

    data_a = _wait_for_job(client, job_a)
    data_b = _wait_for_job(client, job_b)

    assert data_a["status"] == "terminado"
    assert data_b["status"] == "terminado"
    assert data_a["result"]["dataset"]["n_rows"] == 4
    assert data_b["result"]["dataset"]["n_rows"] == 6


def test_dataset_subido_se_borra_al_terminar(client: TestClient) -> None:
    r = client.post(
        "/api/v1/datasets",
        files={"file": ("flows.csv", _small_csv_bytes(), "text/csv")},
    )
    dataset_id = r.json()["dataset_id"]
    matches_antes = list(storage_dir().glob(f"{dataset_id}.*"))
    assert matches_antes, "el archivo deberia existir apenas subido"

    job_id = client.post(
        "/api/v1/audits",
        json={"dataset_id": dataset_id, "label_col": "label", "split_col": "split"},
    ).json()["job_id"]
    data = _wait_for_job(client, job_id)
    assert data["status"] == "terminado"

    matches_despues = list(storage_dir().glob(f"{dataset_id}.*"))
    assert matches_despues == [], "el dataset deberia haberse borrado al terminar el job"


def test_api_key_incorrecta_da_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIA_API_KEY", "clave-correcta")
    with TestClient(app) as c:
        r = c.get("/api/v1/checks", headers={"X-API-Key": "clave-incorrecta"})
        assert r.status_code == 401

        r_sin_clave = c.get("/api/v1/checks")
        assert r_sin_clave.status_code == 401

        r_ok = c.get("/api/v1/checks", headers={"X-API-Key": "clave-correcta"})
        assert r_ok.status_code == 200


def test_poison_endpoint(client: TestClient) -> None:
    r = client.post(
        "/api/v1/datasets",
        files={"file": ("flows.csv", _small_csv_bytes(), "text/csv")},
    )
    dataset_id = r.json()["dataset_id"]

    r = client.post("/api/v1/poison", json={"dataset_id": dataset_id, "label_col": "label"})
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    data = _wait_for_job(client, job_id, kind="poison")
    assert data["status"] == "terminado"
    assert data["kind"] == "poison"


def test_drift_endpoint(client: TestClient) -> None:
    reference_csv = _small_csv_bytes()
    r_ref = client.post("/api/v1/datasets", files={"file": ("ref.csv", reference_csv, "text/csv")})
    r_batch = client.post(
        "/api/v1/datasets", files={"file": ("batch.csv", _small_csv_bytes(), "text/csv")}
    )
    reference_id = r_ref.json()["dataset_id"]
    dataset_id = r_batch.json()["dataset_id"]

    r = client.post(
        "/api/v1/drift",
        json={"dataset_id": dataset_id, "reference_id": reference_id, "label_col": "label"},
    )
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    data = _wait_for_job(client, job_id, kind="drift")
    assert data["status"] == "terminado"
    assert data["kind"] == "drift"


def test_rate_limit_en_endpoints_de_trabajos(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    ids = []
    for _ in range(3):
        r = client.post(
            "/api/v1/datasets",
            files={"file": ("flows.csv", _small_csv_bytes(), "text/csv")},
        )
        ids.append(r.json()["dataset_id"])
    # La subida tambien pasa por el limitador (SEC-02): el limite de 1 se pone
    # despues de subir, con los contadores en cero, para medir solo `/audits`.
    monkeypatch.setenv("VIGIA_RATE_LIMIT_PER_MINUTE", "1")
    reset_rate_limiter()

    # Tres datasets distintos para que un 404 (por borrado tras terminar un job
    # anterior) no se confunda con el 429 que este test busca provocar.
    codes = [
        client.post(
            "/api/v1/audits",
            json={"dataset_id": ds_id, "label_col": "label", "split_col": "split"},
        ).status_code
        for ds_id in ids
    ]
    assert 429 in codes


#: Ids que no son un uuid4 hex pero que `Path.glob` interpreta como patron o
#: como ruta (AUDITORIA-1.0.md, SEC-01).
_IDS_MALICIOSOS = ["*", "?" * 32, "[0-9a-f]*", "../x", "**/x"]


@pytest.mark.parametrize("malicioso", _IDS_MALICIOSOS)
@pytest.mark.parametrize("endpoint", ["audits", "poison", "drift"])
def test_dataset_id_con_comodines_se_rechaza_y_no_toca_datasets_ajenos(
    client: TestClient, endpoint: str, malicioso: str
) -> None:
    """Un id con comodines encontraba los datasets de otros clientes: el
    trabajo los auditaba y, al terminar, `delete_dataset` los borraba todos."""
    ajeno = client.post(
        "/api/v1/datasets", files={"file": ("ajeno.csv", _small_csv_bytes(), "text/csv")}
    ).json()["dataset_id"]

    body = {"dataset_id": malicioso}
    if endpoint == "drift":
        body["reference_id"] = malicioso
    r = client.post(f"/api/v1/{endpoint}", json=body)
    # 422 viene de la validacion, antes de crear el trabajo: no hay ningun
    # trabajo que al terminar pueda borrar lo que su patron encontraba.
    assert r.status_code == 422
    assert list(storage_dir().glob(f"{ajeno}.*")), "el dataset ajeno no deberia haberse borrado"


@pytest.mark.parametrize("malicioso", _IDS_MALICIOSOS)
def test_storage_no_interpreta_el_id_como_patron(malicioso: str) -> None:
    """Defensa en profundidad: aunque algo llame al almacenamiento sin pasar
    por Pydantic, un id con forma invalida no encuentra ni borra nada."""
    from fastapi import HTTPException

    from vigia.api.storage import dataset_path, delete_dataset

    victima = storage_dir() / "0123456789abcdef0123456789abcdef.csv"
    victima.write_bytes(_small_csv_bytes())
    try:
        with pytest.raises(HTTPException) as exc:
            dataset_path(malicioso)
        assert exc.value.status_code == 404
        delete_dataset(malicioso)
        assert victima.exists()
    finally:
        victima.unlink(missing_ok=True)


def test_la_auditoria_acepta_time_format(client: TestClient) -> None:
    """Sin `time_format` en la peticion, una columna de fechas ambigua no tenia
    salida por la API: `leak.temporal` solo podia saltarse."""
    fechas = [f"07/{d:02d}/2017 10:00:00" for d in range(1, 11)]
    df = pl.DataFrame(
        {
            "duration": list(range(15)),
            "ts": fechas + [f"08/{d:02d}/2017 10:00:00" for d in range(1, 6)],
            "split": ["train"] * 10 + ["test"] * 5,
        }
    )
    buf = io.BytesIO()
    df.write_csv(buf)
    dataset_id = client.post(
        "/api/v1/datasets", files={"file": ("f.csv", buf.getvalue(), "text/csv")}
    ).json()["dataset_id"]
    job = client.post(
        "/api/v1/audits",
        json={
            "dataset_id": dataset_id,
            "split_col": "split",
            "time_col": "ts",
            "time_format": "%m/%d/%Y %H:%M:%S",
            "checks": "leak.temporal",
        },
    ).json()["job_id"]
    data = _wait_for_job(client, job)
    assert data["status"] == "terminado", data
    assert "leak.temporal" not in data["result"]["skipped"]
    assert data["result"]["findings"] == []


def test_job_id_con_forma_invalida_da_422(client: TestClient) -> None:
    for kind in ("audits", "poison", "drift"):
        assert client.get(f"/api/v1/{kind}/no-es-un-id").status_code == 422
    assert client.get("/api/v1/audits/no-es-un-id/report.html").status_code == 422
