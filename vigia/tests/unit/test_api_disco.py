"""Subidas huerfanas, cuota de disco y limpieza al arrancar (AUDITORIA-1.0.md, SEC-02).

Sin TTL ni cuota, un cliente podia llenar el disco subiendo archivos que nunca
usaba, y el volumen de Docker los conservaba entre reinicios.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vigia.api import clock, storage
from vigia.api.app import app
from vigia.api.security import reset_rate_limiter
from vigia.api.storage import purge_expired_uploads, storage_dir


class Reloj:
    def __init__(self) -> None:
        self.t = 10.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _reset_rate_limit() -> None:
    reset_rate_limiter()


@pytest.fixture
def reloj(monkeypatch: pytest.MonkeyPatch) -> Reloj:
    r = Reloj()
    monkeypatch.setattr(clock, "now", r)
    return r


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def _csv(n_filas: int = 50) -> bytes:
    filas = "\n".join(f"{i},{i * 2},{'a' if i % 2 else 'b'}" for i in range(n_filas))
    return f"x,y,label\n{filas}\n".encode()


def _subir(client: TestClient, contenido: bytes | None = None) -> str:
    r = client.post("/api/v1/datasets", files={"file": ("f.csv", contenido or _csv(), "text/csv")})
    assert r.status_code == 201, r.text
    return r.json()["dataset_id"]


def _archivos() -> set[Path]:
    return {p for p in storage_dir().iterdir() if p.suffix in storage.VALID_EXTENSIONS}


def test_una_subida_sin_trabajo_se_borra_al_pasar_el_ttl(
    client: TestClient, reloj: Reloj, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_UPLOAD_TTL_MINUTES", "10")
    dataset_id = _subir(client)
    assert any(dataset_id in p.name for p in _archivos())

    reloj.t += 9 * 60
    purge_expired_uploads()
    assert any(dataset_id in p.name for p in _archivos())  # todavia no vencio

    reloj.t += 2 * 60
    assert purge_expired_uploads() == [dataset_id]
    assert not any(dataset_id in p.name for p in _archivos())
    r = client.post("/api/v1/audits", json={"dataset_id": dataset_id})
    assert r.status_code == 404


def test_una_subida_que_un_trabajo_reclamo_no_caduca(
    client: TestClient, reloj: Reloj, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_UPLOAD_TTL_MINUTES", "1")
    dataset_id = _subir(client)
    storage.claim_datasets((dataset_id,))
    reloj.t += 3600
    assert dataset_id not in purge_expired_uploads()
    assert any(dataset_id in p.name for p in _archivos())
    storage.delete_dataset(dataset_id)


def test_la_cuota_rechaza_la_subida_sin_escribirla(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_STORAGE_QUOTA_MB", "1")
    primero = _subir(client, _csv(40_000))  # ~0,5 MB
    antes = _archivos()
    r = client.post("/api/v1/datasets", files={"file": ("g.csv", _csv(40_000), "text/csv")})
    assert r.status_code == 507
    assert _archivos() == antes
    storage.delete_dataset(primero)


def test_la_cuota_tambien_corta_las_subidas_sin_content_length(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_STORAGE_QUOTA_MB", "1")
    primero = _subir(client, _csv(40_000))
    antes = _archivos()
    boundary = "b"
    cuerpo = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="g.csv"\r\n'
        f"Content-Type: text/csv\r\n\r\n".encode()
        + _csv(40_000)
        + f"\r\n--{boundary}--\r\n".encode()
    )

    def trozos() -> Iterator[bytes]:
        for i in range(0, len(cuerpo), 64 * 1024):
            yield cuerpo[i : i + 64 * 1024]

    r = client.post(
        "/api/v1/datasets",
        content=trozos(),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert r.status_code == 507
    assert _archivos() == antes
    storage.delete_dataset(primero)


def test_la_subida_pasa_por_el_limitador_de_peticiones(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VIGIA_RATE_LIMIT_PER_MINUTE", "1")
    primero = _subir(client)
    r = client.post("/api/v1/datasets", files={"file": ("f.csv", _csv(), "text/csv")})
    assert r.status_code == 429
    storage.delete_dataset(primero)


#: Los handles de los candados "vivos" se guardan aca: si el recolector los cierra, el
#: candado se libera y el directorio parece de un proceso muerto.
_CANDADOS: list[object] = []


def _directorio_de_otra_ejecucion(base: Path, nombre: str, *, vivo: bool) -> Path:
    d = base / f"{storage.STORAGE_PREFIX}{nombre}"
    d.mkdir()
    (d / "viejo.csv").write_text("a,b\n1,2\n")
    handle = storage.hold_lock(d)
    if vivo:
        _CANDADOS.append(handle)
    else:
        handle.close()  # el proceso dueno murio: el candado ya no esta tomado
    return d


def test_al_arrancar_se_borran_los_directorios_viejos_con_contenido(tmp_path: Path) -> None:
    viejo = _directorio_de_otra_ejecucion(tmp_path, "viejo", vivo=False)
    storage.remove_stale_dirs(tmp_path)
    assert not viejo.exists()


def test_al_arrancar_no_se_toca_el_directorio_de_un_proceso_vivo(tmp_path: Path) -> None:
    """Con dos procesos sobre el mismo TMPDIR, borrar el directorio del otro
    seria destructivo: su candado lo delata."""
    ajeno = _directorio_de_otra_ejecucion(tmp_path, "ajeno", vivo=True)
    storage.remove_stale_dirs(tmp_path)
    assert (ajeno / "viejo.csv").exists()
    _CANDADOS.pop().close()  # type: ignore[attr-defined]


def test_el_directorio_de_esta_ejecucion_queda_intacto() -> None:
    marcador = storage_dir() / "propio.csv"
    marcador.write_text("a\n1\n")
    storage.remove_stale_dirs(storage_dir().parent)
    assert marcador.exists()
    marcador.unlink()
