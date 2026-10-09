"""Rutas de la API REST (docs/PLAN.md, fase 2.2).

Alcance deliberadamente acotado: los endpoints de datasets solo aceptan CSV y
Parquet (``vigia.api.security.VALID_EXTENSIONS``). Zeek, Suricata EVE y PCAP
quedan fuera de la API por ahora -- ya los cubre la CLI, y PCAP en particular
necesitaria un contenedor aislado aparte (docs/PLAN.md, 2.4.4) que no vale la
pena montar para v1. Si en el futuro se agrega, va en un endpoint separado con
su propio sandboxing, no reutilizando este.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, UploadFile, status
from fastapi.responses import HTMLResponse

import vigia
from vigia.api.errors import log_detail
from vigia.api.jobs import Job, store, submit
from vigia.api.models import (
    ID_PATTERN,
    AuditRequest,
    CheckInfo,
    DatasetUploadResponse,
    DriftRequest,
    HealthResponse,
    JobCreatedResponse,
    JobStatusResponse,
    PoisonRequest,
)
from vigia.api.security import enforce_rate_limit, require_api_key
from vigia.api.storage import dataset_path, save_upload
from vigia.core.engine import run_audit
from vigia.core.findings import Report
from vigia.core.registry import all_checks, module_of
from vigia.report import render_html

router = APIRouter()
health_router = APIRouter()

#: Mismo formato que los ids de dataset: un ``job_id`` con otra forma no puede
#: existir, asi que se rechaza con 422 antes de buscarlo.
JobId = Annotated[str, Path(pattern=ID_PATTERN)]


@health_router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Sin logica: solo confirma que el proceso responde, para el orquestador."""
    return HealthResponse()


@router.post(
    "/datasets",
    response_model=DatasetUploadResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
async def upload_dataset(file: UploadFile) -> DatasetUploadResponse:
    stored = await save_upload(file)
    return DatasetUploadResponse(
        dataset_id=stored.dataset_id, n_rows=stored.n_rows, n_cols=stored.n_cols
    )


def _public_check_error(check_id: str, detail: str) -> str:
    correlation_id = log_detail(f"el check {check_id} fallo", detail)
    return f"{detail.split(':', 1)[0]} (id: {correlation_id})"


#: Rutas (de Windows o de Unix) y direcciones IPv4 que no tienen por que salir por la API.
_RUTA = re.compile(r"(?:[A-Za-z]:)?(?:[\\/][^\s\\/:'\"]+){2,}")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
MAX_MOTIVO = 300


def _public_skip_reason(reason: str) -> str:
    """Motivo de un salto tal como sale por la API. Los motivos de Vigia son frases
    fijas; esto es defensa en profundidad por si alguno trae texto ajeno: se
    tapan rutas e IPs y se acota el largo (VERIFICACION-1.0.md, VER-05)."""
    return _IPV4.sub("<ip>", _RUTA.sub("<ruta>", reason))[:MAX_MOTIVO]


def _anonymize(report: Report, dataset_id: str) -> Report:
    """Reemplaza la ruta interna del servidor por el id opaco del dataset, y el
    mensaje de los checks que fallaron por su tipo y un id de correlacion: el
    mensaje de una excepcion puede traer filas o rutas (AUDITORIA-1.0.md, SEC-06)."""
    report.dataset_path = f"dataset:{dataset_id}"
    report.errors = {
        check_id: _public_check_error(check_id, detail)
        for check_id, detail in report.errors.items()
    }
    report.skipped = {c: _public_skip_reason(r) for c, r in report.skipped.items()}
    return report


def _audit_work(req: AuditRequest) -> Report:
    path = dataset_path(req.dataset_id)
    ctx = vigia.load(
        path,
        label_col=req.label_col,
        split_col=req.split_col,
        time_col=req.time_col,
        src_ip_col=req.src_ip_col,
        dst_ip_col=req.dst_ip_col,
        seed=req.seed,
        time_format=req.time_format,
    )
    return _anonymize(vigia.audit(ctx, checks=req.checks), req.dataset_id)


@router.post(
    "/audits",
    response_model=JobCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
async def launch_audit(req: AuditRequest) -> JobCreatedResponse:
    dataset_path(req.dataset_id)  # 404 temprano si el dataset no existe
    job = submit("audit", (req.dataset_id,), lambda: _audit_work(req))
    return JobCreatedResponse(job_id=job.job_id)


def _get_job_or_404(job_id: str) -> Job:
    job = store().get(job_id)
    if job is None:
        if store().is_expired(job_id):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="el trabajo caduco: los reportes se guardan un tiempo limitado, "
                "volve a lanzar la auditoria",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"trabajo desconocido: {job_id}"
        )
    return job


@router.get(
    "/audits/{job_id}", response_model=JobStatusResponse, dependencies=[Depends(require_api_key)]
)
async def audit_status(job_id: JobId) -> JobStatusResponse:
    job = _get_job_or_404(job_id)
    return JobStatusResponse(**job.to_status_dict())


@router.get("/audits/{job_id}/report.html", dependencies=[Depends(require_api_key)])
async def audit_report_html(job_id: JobId) -> HTMLResponse:
    job = _get_job_or_404(job_id)
    if job.status != "terminado" or job.report is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"el trabajo esta '{job.status}', todavia no hay reporte",
        )
    return HTMLResponse(content=render_html(job.report))


def _poison_work(req: PoisonRequest) -> Report:
    path = dataset_path(req.dataset_id)
    ctx = vigia.load(path, label_col=req.label_col, seed=req.seed)
    return _anonymize(run_audit(ctx, version=vigia.__version__, module="poison"), req.dataset_id)


@router.post(
    "/poison",
    response_model=JobCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
async def launch_poison(req: PoisonRequest) -> JobCreatedResponse:
    dataset_path(req.dataset_id)
    job = submit("poison", (req.dataset_id,), lambda: _poison_work(req))
    return JobCreatedResponse(job_id=job.job_id)


@router.get(
    "/poison/{job_id}", response_model=JobStatusResponse, dependencies=[Depends(require_api_key)]
)
async def poison_status(job_id: JobId) -> JobStatusResponse:
    job = _get_job_or_404(job_id)
    return JobStatusResponse(**job.to_status_dict())


def _drift_work(req: DriftRequest) -> Report:
    from vigia.io.readers import read_dataset, strip_column_names

    path = dataset_path(req.dataset_id)
    ref_path = dataset_path(req.reference_id)
    ctx = vigia.load(path, label_col=req.label_col, seed=req.seed)
    ctx.reference = strip_column_names(read_dataset(ref_path))
    return _anonymize(run_audit(ctx, version=vigia.__version__, module="drift"), req.dataset_id)


@router.post(
    "/drift",
    response_model=JobCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
async def launch_drift(req: DriftRequest) -> JobCreatedResponse:
    dataset_path(req.dataset_id)
    dataset_path(req.reference_id)
    job = submit("drift", (req.dataset_id, req.reference_id), lambda: _drift_work(req))
    return JobCreatedResponse(job_id=job.job_id)


@router.get(
    "/drift/{job_id}", response_model=JobStatusResponse, dependencies=[Depends(require_api_key)]
)
async def drift_status(job_id: JobId) -> JobStatusResponse:
    job = _get_job_or_404(job_id)
    return JobStatusResponse(**job.to_status_dict())


@router.get("/checks", response_model=list[CheckInfo], dependencies=[Depends(require_api_key)])
async def list_checks() -> list[CheckInfo]:
    return [
        CheckInfo(id=c.id, name=c.name, category=c.category, module=module_of(c))
        for c in all_checks(None)
    ]
