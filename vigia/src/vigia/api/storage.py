"""Almacenamiento temporal de datasets subidos (docs/PLAN.md, 2.4.1 y 2.4.2).

Cada dataset subido vive en su propio archivo dentro de un directorio
temporal, identificado por un id opaco (no el nombre original: evita choques
y no expone rutas del cliente). El llamador es responsable de borrar el
archivo cuando ya no hace falta -- en la API eso lo hace el manejador del job
al terminar (ver ``vigia.api.jobs``).
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import re
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import IO

import polars as pl
from fastapi import HTTPException, UploadFile, status

from vigia.api import clock
from vigia.api.config import load_settings
from vigia.api.errors import log_exception
from vigia.api.models import ID_PATTERN
from vigia.api.security import VALID_EXTENSIONS, max_upload_bytes, validate_extension
from vigia.io.readers import csv_options, read_csv_sample

#: Prefijo del directorio de esta ejecucion del servidor, bajo el directorio
#: temporal. Un `mkdtemp` por proceso alcanza: las subidas no sobreviven un
#: reinicio, y las de una ejecucion anterior se borran al arrancar.
STORAGE_PREFIX = "vigia_api_"
_LOCK_NAME = ".lock"


def _try_lock(handle: IO[bytes]) -> None:
    """Toma un candado exclusivo sin esperar; ``OSError`` si otro lo tiene.

    El sistema operativo lo libera solo cuando el proceso dueno muere, aunque
    sea por un kill o un OOM: por eso sirve para saber si un directorio
    pertenece a un proceso vivo, cosa que un archivo con el PID no puede
    garantizar (el PID se reutiliza y no hay una forma portable de saber si
    esta vivo sin dependencias).
    """
    if sys.platform == "win32":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def hold_lock(directory: Path) -> IO[bytes]:
    """Marca ``directory`` como de un proceso vivo mientras el handle siga abierto."""
    handle = (directory / _LOCK_NAME).open("a+b")
    try:
        _try_lock(handle)
    except OSError:
        handle.close()
        raise
    return handle


def remove_stale_dirs(base: Path | None = None) -> None:
    """Borra los directorios ``vigia_api_*`` de ejecuciones anteriores, con
    contenido (AUDITORIA-1.0.md, SEC-02): el volumen de Docker sobrevive a los
    reinicios y las subidas de un proceso que murio se quedaban para siempre.

    Con dos procesos sobre el mismo ``TMPDIR`` esto seria destructivo si
    borrara el directorio del otro; por eso solo borra los que no tienen el
    candado tomado (``hold_lock``). Un directorio sin archivo de candado viene
    de una version anterior: se borra solo si esta vacio, como antes.
    """
    root = base if base is not None else Path(tempfile.gettempdir())
    for stale in root.glob(f"{STORAGE_PREFIX}*"):
        if not stale.is_dir() or stale == _STORAGE_DIR:
            continue
        lock = stale / _LOCK_NAME
        if not lock.exists():
            with contextlib.suppress(OSError):
                stale.rmdir()
            continue
        try:
            handle = hold_lock(stale)
        except OSError:
            continue  # lo tiene un proceso vivo
        handle.close()
        shutil.rmtree(stale, ignore_errors=True)


#: Se asigna mas abajo; `remove_stale_dirs` lo necesita para no tocar el propio.
_STORAGE_DIR: Path = Path()
remove_stale_dirs()
_STORAGE_DIR = Path(tempfile.mkdtemp(prefix=STORAGE_PREFIX))
_LOCK_HANDLE = hold_lock(_STORAGE_DIR)
# Al salir el proceso no queda ni el directorio ni subidas a medias.
atexit.register(shutil.rmtree, _STORAGE_DIR, ignore_errors=True)

#: Se lee en trozos para poder cortar el stream apenas se supera el limite,
#: en vez de esperar a tener el archivo entero en memoria o en disco.
_CHUNK_SIZE = 1024 * 1024


@dataclass
class _Upload:
    created: float
    size: int = 0
    claimed: bool = False


#: Subidas vivas: ``dataset_id -> estado``. Sirve para la cuota (suma de
#: tamanos), para el TTL (``created``) y para no borrar lo que un trabajo ya
#: reclamo (``claimed``, incluso si espera en la cola).
_UPLOADS: dict[str, _Upload] = {}
_UPLOADS_LOCK = Lock()


def used_bytes() -> int:
    with _UPLOADS_LOCK:
        return sum(u.size for u in _UPLOADS.values())


def claim_datasets(dataset_ids: tuple[str, ...]) -> None:
    """Un trabajo usa estos datasets: no caducan por TTL mientras espera o corre.
    Se liberan al borrarlos (``delete_dataset``), cuando el trabajo termina."""
    with _UPLOADS_LOCK:
        for dataset_id in dataset_ids:
            if dataset_id in _UPLOADS:
                _UPLOADS[dataset_id].claimed = True


def purge_expired_uploads() -> list[str]:
    """Borra las subidas que ningun trabajo reclamo en ``VIGIA_UPLOAD_TTL_MINUTES``.
    Devuelve los ids borrados."""
    ttl = load_settings().upload_ttl_minutes * 60.0
    now = clock.now()
    with _UPLOADS_LOCK:
        vencidos = [i for i, u in _UPLOADS.items() if not u.claimed and now - u.created > ttl]
    for dataset_id in vencidos:
        delete_dataset(dataset_id)
    return vencidos


@dataclass
class StoredDataset:
    dataset_id: str
    path: Path
    original_filename: str
    n_rows: int
    n_cols: int


def storage_dir() -> Path:
    return _STORAGE_DIR


async def save_upload(file: UploadFile) -> StoredDataset:
    """Guarda un archivo subido, validando tamano, extension y contenido.

    El limite de tamano lo aplica antes ``BodyLimitMiddleware``, que corta el
    cuerpo en la red (AUDITORIA-1.0.md, SEC-05); aca queda como defensa para
    quien llame a esta funcion sin el middleware, y es el tope exacto del
    archivo (el del middleware suma el margen del multipart). La
    validacion de contenido intenta leerlo con polars; un archivo que se hace
    pasar por CSV o Parquet pero no lo es se rechaza igual, sin confiar en la
    extension declarada.
    """
    suffix = validate_extension(file.filename)
    limit = max_upload_bytes()
    quota = load_settings().storage_quota_bytes

    declared = file.size
    if declared is not None and declared > limit:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"archivo de {declared} bytes supera el limite de {limit} bytes",
        )
    if declared is not None and used_bytes() + declared > quota:
        raise _quota_exceeded()

    dataset_id = uuid.uuid4().hex
    dest = _STORAGE_DIR / f"{dataset_id}{suffix}"

    # Se registra antes de escribir para que la cuota cuente lo que hay en
    # vuelo: dos subidas simultaneas no pueden pasarse juntas.
    upload = _Upload(created=clock.now())
    with _UPLOADS_LOCK:
        _UPLOADS[dataset_id] = upload

    written = 0
    try:
        with dest.open("wb") as out:
            while chunk := await file.read(_CHUNK_SIZE):
                written += len(chunk)
                upload.size = written
                if written > limit:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=f"la subida supera el limite de {limit} bytes",
                    )
                if used_bytes() > quota:
                    raise _quota_exceeded()
                out.write(chunk)
    except BaseException:
        delete_dataset(dataset_id)
        dest.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    if written == 0:
        delete_dataset(dataset_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="archivo vacio")

    upload.created = clock.now()  # el TTL cuenta desde que termino de subir
    try:
        n_rows, n_cols = await asyncio.to_thread(_validate_content, dest, suffix)
    except HTTPException:
        delete_dataset(dataset_id)
        raise
    return StoredDataset(
        dataset_id=dataset_id,
        path=dest,
        original_filename=file.filename or dest.name,
        n_rows=n_rows,
        n_cols=n_cols,
    )


def _quota_exceeded() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
        detail="el servidor no tiene espacio para otra subida ahora; proba mas tarde",
    )


def _validate_content(path: Path, suffix: str) -> tuple[int, int]:
    """Confirma que el contenido es el que declara la extension y devuelve
    ``(filas, columnas)``, **sin materializar el archivo**.

    Antes se hacia ``pl.read_parquet(path)`` / ``pl.read_csv(path)`` completo,
    dentro del event loop: un Parquet de 114 KiB que descomprime a 50 M de filas
    agotaba la memoria y, mientras se leia una subida grande, el servidor no
    contestaba (AUDITORIA-1.0.md, SEC-04 y PERF-02). Ahora el Parquet se mira por
    su pie (esquema y numero de filas) y el CSV se lee solo en una muestra, con
    el mismo lector que la auditoria (incluido el reintento en Windows-1252,
    COR-06); las filas se cuentan sin cargar nada. Corre en un hilo.
    """
    settings = load_settings()
    try:
        if suffix in (".parquet", ".pq"):
            n_cols = len(pl.read_parquet_schema(path))
            n_rows = int(pl.scan_parquet(path).select(pl.len()).collect().item())
        else:
            n_cols = read_csv_sample(path).width
            # "utf8-lossy" solo para contar: un byte raro no tumba el conteo y
            # no cambia cuantas filas hay.
            lazy = pl.scan_csv(path, encoding="utf8-lossy", **csv_options())  # type: ignore[arg-type]
            n_rows = int(lazy.select(pl.len()).collect().item())
    except Exception as exc:
        path.unlink(missing_ok=True)
        correlation_id = log_exception(f"subida ilegible como {suffix}", exc)
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"el contenido no se pudo leer como {suffix} (id: {correlation_id})",
        ) from exc
    if n_rows > settings.max_rows or n_rows * max(n_cols, 1) * 8 > settings.max_expanded_bytes:
        path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"el dataset tiene {n_rows} filas x {n_cols} columnas y supera el tope del "
                f"servidor ({settings.max_rows} filas, {settings.max_expanded_mb} MB en memoria)"
            ),
        )
    return n_rows, n_cols


def _candidates(dataset_id: str) -> list[Path]:
    """Archivos que pueden corresponder a ``dataset_id``, sin interpretar patrones.

    Antes se buscaban con ``glob(f"{dataset_id}.*")``: un id como ``*`` o
    ``../algo`` encontraba datasets ajenos o archivos fuera del directorio, y
    `delete_dataset` los borraba (AUDITORIA-1.0.md, SEC-01). Pydantic ya
    rechaza esos ids en la API; esto es defensa en profundidad para cualquier
    otro llamador: un id con otra forma no encuentra nada, y cada ruta se
    resuelve y se confirma dentro de `_STORAGE_DIR` antes de usarla.
    """
    if not re.fullmatch(ID_PATTERN, dataset_id):
        return []
    root = _STORAGE_DIR.resolve()
    out = []
    for suffix in VALID_EXTENSIONS:
        p = (_STORAGE_DIR / f"{dataset_id}{suffix}").resolve()
        if p.parent == root and p.is_file():
            out.append(p)
    return out


def dataset_path(dataset_id: str) -> Path:
    matches = _candidates(dataset_id)
    if not matches:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"dataset desconocido: {dataset_id}"
        )
    return matches[0]


def reset_uploads() -> None:
    """Borra todas las subidas registradas. Uso exclusivo de tests: una subida que
    dejo un test no puede aparecer en lo que purga el siguiente (VERIFICACION-1.0.md,
    VER-02)."""
    with _UPLOADS_LOCK:
        pendientes = list(_UPLOADS)
    for dataset_id in pendientes:
        delete_dataset(dataset_id)


def delete_dataset(dataset_id: str) -> None:
    """Borra el archivo del dataset si existe. No falla si ya se borro."""
    with _UPLOADS_LOCK:
        _UPLOADS.pop(dataset_id, None)
    for match in _candidates(dataset_id):
        match.unlink(missing_ok=True)
