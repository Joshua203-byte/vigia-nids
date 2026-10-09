"""Vigía — control de calidad continuo para los datos de modelos de ciberseguridad.

SDK mínimo (sección 14.3 del documento maestro):

    import vigia

    ds = vigia.load("data/flows.parquet", label_col="Label", split_col="split")
    report = vigia.audit(ds, checks="all", seed=42)
    print(report.to_json())
"""

from __future__ import annotations

from importlib import metadata as _metadata
from pathlib import Path

from vigia.core.context import AuditContext
from vigia.core.engine import run_audit
from vigia.core.findings import Finding, Report
from vigia.core.hashing import file_sha256
from vigia.io.readers import detect_column, read_dataset, strip_column_names
from vigia.profiles import apply_label_groups, load_profile

try:
    # La versión se declara una sola vez, en `pyproject.toml`, y sale de los
    # metadatos del paquete instalado. Escrita también acá, un tag mal puesto o
    # un descuido publicaban un paquete que decía otra versión
    # (AUDITORIA-1.0.md, CI-01).
    __version__ = _metadata.version("vigia-nids")
except _metadata.PackageNotFoundError:  # pragma: no cover - solo sin instalar
    # Importado desde un árbol sin instalar: no hay metadatos. Una versión que
    # se reconoce como falsa es mejor que fallar al importar o inventar una.
    __version__ = "0.0.0+desconocida"

__all__ = [
    "AuditContext",
    "Finding",
    "Report",
    "__version__",
    "audit",
    "load",
]


def load(
    path: str | Path,
    *,
    label_col: str | None = None,
    split_col: str | None = None,
    time_col: str | None = None,
    src_ip_col: str | None = None,
    dst_ip_col: str | None = None,
    src_port_col: str | None = None,
    dst_port_col: str | None = None,
    protocol_col: str | None = None,
    strip_names: bool = True,
    seed: int = 42,
    event_type: str | None = "flow",
    profile: str | None = None,
    time_format: str | None = None,
    **config: object,
) -> AuditContext:
    """Carga un dataset y arma el contexto de auditoría.

    Las columnas que no se especifican se detectan por nombre (ver
    ``vigia.io.readers.detect_column``); si no se encuentran, los checks que
    dependen de ellas se saltan y lo dicen en el reporte.

    ``event_type`` solo aplica a los EVE de Suricata: elige qué tipo de evento
    auditar de un archivo que los mezcla.

    ``profile`` (R17) fija roles de columna conocidos para un dataset público
    (ver ``vigia.profiles``). Un ``*_col`` explícito siempre gana sobre el
    perfil, y el perfil siempre gana sobre la detección automática.
    Si el perfil trae ``label_groups``, la etiqueta se agrupa por prefijos y la
    original queda en ``__label_original``.
    Si el perfil trae ``csv_columns``, los CSV se leen sin cabecera con esos
    nombres (UGR'16).
    Si el perfil trae ``time_format``, se usa para interpretar la columna de
    tiempo salvo que se pase uno explícito (opción ``time_format``).
    Metadatos del perfil sin rol asociado (IPs atacantes, ventanas de ataque,
    errores conocidos) quedan disponibles en ``ctx.config["profile"]`` para
    que quien revise el reporte los tenga a mano; ningún check depende de
    ellos.
    """
    profile_data = load_profile(profile) if profile else None
    roles = profile_data.get("column_roles", {}) if profile_data else {}

    csv_columns = profile_data.get("csv_columns") if profile_data else None
    df = read_dataset(path, event_type=event_type, csv_columns=csv_columns)
    if strip_names:
        df = strip_column_names(df)

    if profile_data is not None:
        config = {**config, "profile": profile_data}
    # Un formato de tiempo resuelve la ambigüedad día/mes que `leak.temporal`
    # no adivina. El explícito gana sobre el del perfil, como las columnas.
    fmt = time_format or (profile_data.get("time_format") if profile_data else None)
    if fmt:
        config = {**config, "time_format": fmt}

    label_col = label_col or roles.get("label_col") or detect_column(df, "label")
    groups = profile_data.get("label_groups") if profile_data else None
    if groups and label_col and label_col in df.columns:
        df = apply_label_groups(df, label_col, groups)

    # Declaradas = pedidas con una opción o con el perfil; la detección por
    # nombre no cuenta (ver `AuditContext.declared_roles`).
    declared_time = time_col or roles.get("time_col")
    declared_src = src_ip_col or roles.get("src_ip_col")
    declared_dst = dst_ip_col or roles.get("dst_ip_col")
    declared = frozenset(c for c in (declared_time, declared_src, declared_dst) if c)

    return AuditContext(
        df=df,
        path=str(path),
        sha256=file_sha256(path),
        label_col=label_col,
        split_col=split_col or roles.get("split_col") or detect_column(df, "split"),
        time_col=declared_time or detect_column(df, "time"),
        src_ip_col=declared_src or detect_column(df, "src_ip"),
        dst_ip_col=declared_dst or detect_column(df, "dst_ip"),
        src_port_col=src_port_col or roles.get("src_port_col") or detect_column(df, "src_port"),
        dst_port_col=dst_port_col or roles.get("dst_port_col") or detect_column(df, "dst_port"),
        protocol_col=protocol_col or roles.get("protocol_col") or detect_column(df, "protocol"),
        seed=seed,
        declared_roles=declared,
        config=dict(config),
    )


def audit(ctx: AuditContext, checks: str | None = "all", seed: int | None = None) -> Report:
    """Ejecuta la auditoría sobre un contexto ya cargado."""
    if seed is not None:
        ctx.seed = seed
    return run_audit(ctx, checks=checks, version=__version__)
