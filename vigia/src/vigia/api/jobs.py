"""Cola de trabajos en proceso (docs/PLAN.md, 2.3): sin Celery ni Redis.

Un diccionario ``job_id -> Job`` en memoria alcanza para v1: una sola
instancia, sin necesidad de sobrevivir un reinicio. Cada job pesado
(auditoria, envenenamiento, deriva) corre en un hilo aparte via
``asyncio.to_thread`` para no bloquear el event loop, porque polars y
scikit-learn son sincronicos.

Nunca se usa pickle para nada de esto: el estado vive solo en memoria como
objetos Python nativos, y lo que se expone por HTTP sale de ``Report.to_dict()``.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Literal

from fastapi import HTTPException, status

from vigia.api import clock
from vigia.api.config import load_settings
from vigia.api.errors import log_exception
from vigia.api.storage import claim_datasets, delete_dataset
from vigia.core.findings import Report

log = logging.getLogger(__name__)

#: Referencias fuertes a las tareas de fondo lanzadas por `launch()`. Sin
#: esto, `asyncio.create_task` solo queda referenciada por el event loop, que
#: guarda una referencia debil: el recolector de basura puede liberar la
#: tarea (y cancelarla) antes de que termine. Ver la nota de la doc de
#: asyncio sobre "Important: Save a reference to the result of this function".
_BACKGROUND_TASKS: set[asyncio.Task[None]] = set()

#: Cuantos ids caducados se recuerdan para contestar "caduco" en vez de "no existe".
MAX_REMEMBERED_EXPIRED = 1000


def public_message(exc: BaseException, correlation_id: str) -> str:
    """Lo que ve el cliente cuando un trabajo falla: nada del mensaje original.

    Una columna inexistente es el unico error del cliente que se distingue:
    el nombre lo puso el, asi que decirle que esta mal no filtra nada.
    """
    import polars as pl

    if isinstance(exc, pl.exceptions.ColumnNotFoundError):
        return f"alguna de las columnas indicadas no existe en el dataset (id: {correlation_id})"
    return (
        f"el trabajo fallo por un error interno (id: {correlation_id}); "
        "si se repite, avisale a quien administra el servidor con ese id"
    )


JobStatus = Literal["pendiente", "corriendo", "terminado", "fallido"]
JobKind = Literal["audit", "poison", "drift"]


@dataclass
class Job:
    job_id: str
    kind: JobKind
    status: JobStatus = "pendiente"
    report: Report | None = None
    error: str | None = None
    created_at: float = field(default_factory=clock.now)
    #: Cuando termino (o fallo); sirve para caducar el reporte.
    finished_at: float | None = None
    #: Datasets a borrar cuando el job termina (terminado o fallido), sea cual
    #: sea el resultado. `drift` sube dos (lote y referencia).
    dataset_ids: tuple[str, ...] = ()

    def to_status_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"job_id": self.job_id, "kind": self.kind, "status": self.status}
        if self.status == "terminado" and self.report is not None:
            out["result"] = self.report.to_dict()
        if self.status == "fallido" and self.error is not None:
            out["error"] = self.error
        return out


class JobStore:
    """Registro de trabajos en memoria, con lock porque distintos hilos
    (uno por job) escriben el mismo diccionario."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        #: Ids de trabajos que caducaron, para contestar 410 y no 404. Acotado:
        #: no es un registro, solo una ayuda para que el mensaje sea honesto.
        self._expired: OrderedDict[str, None] = OrderedDict()
        self._lock = Lock()

    def create(self, kind: JobKind, dataset_ids: tuple[str, ...] = ()) -> Job:
        job = Job(job_id=uuid.uuid4().hex, kind=kind, dataset_ids=dataset_ids)
        with self._lock:
            self._evict_over_cap(load_settings().max_stored_jobs - 1)
            self._jobs[job.job_id] = job
        return job

    def _evict_over_cap(self, keep: int) -> None:
        """Con el lock tomado: si hay mas de ``keep`` trabajos, descarta los
        terminados mas viejos. Nunca toca uno pendiente o corriendo."""
        terminados = sorted(
            (j for j in self._jobs.values() if j.finished_at is not None),
            key=lambda j: j.finished_at or 0.0,
        )
        for job in terminados:
            if len(self._jobs) <= keep:
                break
            self._forget(job.job_id)

    def _forget(self, job_id: str) -> None:
        del self._jobs[job_id]
        self._expired[job_id] = None
        while len(self._expired) > MAX_REMEMBERED_EXPIRED:
            self._expired.popitem(last=False)

    def purge_expired(self) -> list[str]:
        """Borra los trabajos terminados o fallidos (y su reporte) que pasaron
        ``VIGIA_REPORT_TTL_MINUTES`` (docs/PLAN.md, "Despliegue")."""
        ttl = load_settings().report_ttl_minutes * 60.0
        now = clock.now()
        with self._lock:
            vencidos = [
                j.job_id
                for j in self._jobs.values()
                if j.finished_at is not None and now - j.finished_at > ttl
            ]
            for job_id in vencidos:
                self._forget(job_id)
        return vencidos

    def is_expired(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._expired

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _set(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for key, value in changes.items():
                setattr(job, key, value)

    def mark_running(self, job_id: str) -> None:
        self._set(job_id, status="corriendo")

    def mark_done(self, job_id: str, report: Report) -> None:
        self._set(job_id, status="terminado", report=report, finished_at=clock.now())
        self._cleanup_datasets(job_id)

    def mark_failed(self, job_id: str, error: str) -> None:
        self._set(job_id, status="fallido", error=error, finished_at=clock.now())
        self._cleanup_datasets(job_id)

    def _cleanup_datasets(self, job_id: str) -> None:
        """Borra los datasets subidos asociados al job: el archivo temporal no
        tiene por que sobrevivir a un trabajo ya terminado (docs/PLAN.md, 2.4)."""
        job = self.get(job_id)
        if job is None:
            return
        for dataset_id in job.dataset_ids:
            try:
                delete_dataset(dataset_id)
            except Exception:
                log.warning("no se pudo borrar el dataset %s del job %s", dataset_id, job_id)


_STORE = JobStore()


def store() -> JobStore:
    return _STORE


async def run_job(job_id: str, work: Callable[[], Report]) -> None:
    """Ejecuta ``work`` (sincronico, potencialmente lento) en un hilo aparte y
    actualiza el estado del job. ``work`` no debe lanzar mas que Exception
    corriente. Al cliente le llega un mensaje generico con un id de
    correlacion; el detalle y el traceback quedan en el log (SEC-06)."""
    _STORE.mark_running(job_id)
    try:
        report = await asyncio.to_thread(work)
    except Exception as exc:
        correlation_id = log_exception(f"el job {job_id} fallo", exc)
        _STORE.mark_failed(job_id, public_message(exc, correlation_id))
        return
    _STORE.mark_done(job_id, report)


#: Trabajos corriendo ahora y cola de los que esperan su turno. Solo se tocan
#: desde el event loop (``submit`` y el final de cada tarea), asi que no
#: necesitan lock.
_RUNNING = 0
_QUEUE: deque[tuple[str, Callable[[], Report]]] = deque()

#: Segundos que se sugieren esperar cuando la cola esta llena.
RETRY_AFTER_SECONDS = 30


def reset_scheduler() -> None:
    """Vacia la cola y el contador. Uso exclusivo de tests: cada `TestClient`
    abre su propio event loop y cancela lo que dejo en vuelo."""
    global _RUNNING
    _RUNNING = 0
    _QUEUE.clear()


def submit(kind: JobKind, dataset_ids: tuple[str, ...], work: Callable[[], Report]) -> Job:
    """Crea un trabajo y lo corre cuando haya lugar, o lo deja ``pendiente`` en la
    cola. Con la cola llena rechaza con 503 y ``Retry-After`` *antes* de crear
    nada: el dataset sigue ahi y el cliente puede reintentar con el mismo id.

    Los datasets quedan reclamados desde ahora: un trabajo que espera en la
    cola no puede perder su archivo por el TTL de subidas.
    """
    settings = load_settings()
    if settings.max_concurrent_jobs <= _RUNNING and len(_QUEUE) >= settings.max_queued_jobs:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="hay demasiados trabajos en curso; proba de nuevo en unos segundos",
            headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
        )
    job = _STORE.create(kind, dataset_ids=dataset_ids)
    claim_datasets(dataset_ids)
    if settings.max_concurrent_jobs > _RUNNING:
        launch(job.job_id, work)
    else:
        _QUEUE.append((job.job_id, work))
    return job


async def _run_and_continue(job_id: str, work: Callable[[], Report]) -> None:
    global _RUNNING
    try:
        await run_job(job_id, work)
    except asyncio.CancelledError:
        _RUNNING -= 1  # el loop se esta cerrando: no se arrancan mas trabajos
        raise
    _RUNNING -= 1
    _start_waiting()


def _start_waiting() -> None:
    settings = load_settings()
    while _QUEUE and settings.max_concurrent_jobs > _RUNNING:
        job_id, work = _QUEUE.popleft()
        launch(job_id, work)


def launch(job_id: str, work: Callable[[], Report]) -> None:
    """Lanza el trabajo como tarea de fondo, reteniendo una referencia fuerte.

    Usar esto en vez de ``asyncio.create_task(run_job(...))`` directo: sin la
    referencia guardada en ``_BACKGROUND_TASKS``, la tarea solo cuelga del
    event loop por una referencia debil y el recolector de basura puede
    liberarla (cancelando el job a mitad de camino) antes de que termine.
    """
    global _RUNNING
    _RUNNING += 1
    task = asyncio.create_task(_run_and_continue(job_id, work))
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
