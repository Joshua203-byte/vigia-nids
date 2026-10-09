"""Validacion de subidas sin leerlas enteras (AUDITORIA-1.0.md, SEC-04, PERF-02, COR-06).

`_validate_content` hacia `pl.read_parquet` / `pl.read_csv` del archivo completo
dentro del event loop: un Parquet de 114 KiB que descomprime a 50 M de filas
agotaba la memoria, y mientras una subida grande se leia el servidor no
contestaba ni `/health`.
"""

from __future__ import annotations

import io
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from fastapi.testclient import TestClient

from vigia.api import storage
from vigia.api.app import app
from vigia.api.security import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    reset_rate_limiter()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def _parquet(df: pl.DataFrame) -> bytes:
    buf = io.BytesIO()
    df.write_parquet(buf)
    return buf.getvalue()


def test_un_parquet_que_se_expande_se_rechaza_sin_descomprimirlo(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_MAX_ROWS", "10000")
    bomba = _parquet(pl.DataFrame({"x": pl.Series([0] * 2_000_000, dtype=pl.Int64)}))
    assert len(bomba) < 100_000  # chico en disco, enorme en memoria

    def no_leer(*args: Any, **kwargs: Any) -> pl.DataFrame:
        raise AssertionError("la validacion no debe materializar el Parquet")

    monkeypatch.setattr(pl, "read_parquet", no_leer)
    r = client.post(
        "/api/v1/datasets", files={"file": ("bomba.parquet", bomba, "application/octet-stream")}
    )
    assert r.status_code == 413
    assert not [p for p in storage.storage_dir().iterdir() if p.suffix == ".parquet"]


def test_un_parquet_normal_sigue_subiendo_con_sus_filas_y_columnas(client: TestClient) -> None:
    df = pl.DataFrame({"a": list(range(1000)), "label": ["x", "y"] * 500})
    r = client.post("/api/v1/datasets", files={"file": ("d.parquet", _parquet(df), "x/y")})
    assert r.status_code == 201
    assert (r.json()["n_rows"], r.json()["n_cols"]) == (1000, 2)


def test_un_csv_se_valida_con_una_muestra_y_las_filas_siguen_exactas(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    filas = 25_000  # mas que la muestra
    cuerpo = "x,y,label\n" + "\n".join(f"{i},{i * 2},{'a' if i % 2 else 'b'}" for i in range(filas))
    lecturas: list[Any] = []
    original = pl.read_csv

    def espia(*args: Any, **kwargs: Any) -> pl.DataFrame:
        lecturas.append(kwargs.get("n_rows"))
        return original(*args, **kwargs)

    monkeypatch.setattr(pl, "read_csv", espia)
    r = client.post("/api/v1/datasets", files={"file": ("f.csv", cuerpo.encode(), "text/csv")})
    assert r.status_code == 201
    assert r.json() == {"dataset_id": r.json()["dataset_id"], "n_rows": filas, "n_cols": 3}
    assert lecturas and all(n is not None for n in lecturas)  # nunca el archivo entero


def test_un_csv_en_cp1252_sube_como_en_la_cli(client: TestClient) -> None:
    """CIC-IDS2017 etiqueta los ataques web con un guion largo en Windows-1252
    (``Web Attack \\x96 Brute Force``): la CLI lo lee, la API lo rechazaba."""
    cuerpo = b"x,Label\n1,Web Attack \x96 Brute Force\n2,BENIGN\n3,BENIGN\n"
    r = client.post("/api/v1/datasets", files={"file": ("web.csv", cuerpo, "text/csv")})
    assert r.status_code == 201, r.text
    assert (r.json()["n_rows"], r.json()["n_cols"]) == (3, 2)


def test_validar_no_bloquea_el_event_loop(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    liberar = threading.Event()
    original = storage._validate_content

    def lenta(path: Path, suffix: str) -> tuple[int, int]:
        liberar.wait(5)
        return original(path, suffix)

    monkeypatch.setattr(storage, "_validate_content", lenta)
    resultado: dict[str, int] = {}

    def subir() -> None:
        r = client.post(
            "/api/v1/datasets", files={"file": ("f.csv", b"a,b\n1,2\n3,4\n", "text/csv")}
        )
        resultado["status"] = r.status_code

    hilo = threading.Thread(target=subir)
    hilo.start()
    time.sleep(0.3)  # la subida ya esta adentro de la validacion
    t0 = time.monotonic()
    assert client.get("/health").status_code == 200
    asyncio_libre = time.monotonic() - t0 < 2.0
    liberar.set()
    hilo.join(10)
    assert asyncio_libre, "/health tuvo que esperar a que terminara la validacion"
    assert resultado["status"] == 201
