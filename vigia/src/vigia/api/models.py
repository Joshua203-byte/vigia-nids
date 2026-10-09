"""Modelos Pydantic de entrada y salida de la API."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, StringConstraints

#: Forma exacta de los ids que genera la API (`uuid.uuid4().hex`). Sin esta
#: restriccion el id llegaba crudo a `Path.glob`, que interpreta `*`, `?`,
#: `[...]` y `..`: un cliente podia auditar o borrar datasets ajenos y alcanzar
#: archivos fuera del directorio de subidas (AUDITORIA-1.0.md, SEC-01).
ID_PATTERN = r"^[0-9a-f]{32}$"
OpaqueId = Annotated[str, StringConstraints(pattern=ID_PATTERN)]


class DatasetUploadResponse(BaseModel):
    dataset_id: str
    n_rows: int
    n_cols: int


class JobCreatedResponse(BaseModel):
    job_id: str


class JobStatusResponse(BaseModel):
    job_id: str
    kind: Literal["audit", "poison", "drift"]
    status: Literal["pendiente", "corriendo", "terminado", "fallido"]
    result: dict[str, Any] | None = None
    error: str | None = None


class AuditRequest(BaseModel):
    dataset_id: OpaqueId
    label_col: str | None = None
    split_col: str | None = None
    time_col: str | None = None
    src_ip_col: str | None = None
    dst_ip_col: str | None = None
    #: Formato de la columna de tiempo cuando día y mes son ambiguos: sin esto
    #: `leak.temporal` solo puede saltarse con ese motivo.
    time_format: str | None = None
    checks: str = "all"
    seed: int = 42


class PoisonRequest(BaseModel):
    dataset_id: OpaqueId
    label_col: str | None = None
    seed: int = 42


class DriftRequest(BaseModel):
    dataset_id: OpaqueId
    reference_id: OpaqueId
    label_col: str | None = None
    seed: int = 42


class CheckInfo(BaseModel):
    id: str
    name: str
    category: str
    module: str


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
