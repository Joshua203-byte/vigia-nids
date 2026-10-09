"""Auditoría en modo streaming, para datasets que no entran en memoria.

docs/PLAN.md, fase 1.5: no todos los checks se pueden expresar en modo
lazy —`labels.noise` necesita entrenar un modelo, y varios otros necesitan
todas las filas en memoria a la vez para poder referenciarlas por índice—,
pero los de duplicados y validez sí, porque son agregaciones.

Este módulo no reutiliza las clases de `vigia.checks`: esas operan sobre un
`pl.DataFrame` ya cargado (`ctx.df.get_column(...)`, máscaras booleanas
materializadas) y forzarlas a un `pl.LazyFrame` requeriría reescribirlas
igual. En cambio, cada función de acá calcula con expresiones lazy
exactamente lo mismo que su check equivalente, y arma el mismo tipo de
`Finding`.

Mejor un reporte explícito de qué corrió y qué no, que fingir que la
auditoría fue completa.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import polars as pl

from vigia.core.context import CheckSkipped
from vigia.core.findings import Finding, Report
from vigia.io.readers import CSV_SUFFIXES, csv_options, detect_column, promoted_int_overrides
from vigia.profiles import label_groups_expr, load_profile

#: Checks del auditor que sí tienen una versión streaming en este módulo.
STREAMING_CHECKS = ("dup.exact", "dup.cross_split", "validity.nan_inf", "validity.constant")

_NO_FEATURES = "el dataset no tiene columnas de características"

#: El resto de los checks del auditor: no corren en modo streaming y se
#: reportan como saltados con el motivo, en vez de quedar mudos.
_NON_STREAMING_REASON = "no soportado en modo streaming: requiere el dataset completo en memoria"


def _strip_names(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Quita los espacios de los nombres de columna, como hace `vigia.load`.

    Sin esto `--label-col Label` sobre un CSV de CICFlowMeter (`" Label"`) fallaba
    con `ColumnNotFoundError` y salía con código 1, que significa "hay hallazgos"
    (AUDITORIA-1.0.md, COR-02).
    """
    nombres = lf.collect_schema().names()
    cambios = {c: c.strip() for c in nombres if c != c.strip()}
    return lf.rename(cambios) if cambios else lf


def _scan(path: str | Path, csv_columns: list[str] | None = None) -> pl.LazyFrame:
    """Abre un CSV o Parquet en modo lazy, sin cargarlo en memoria.

    ``csv_columns`` (de un perfil) lee el CSV sin cabecera con esos nombres.
    """
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix in (".parquet", ".pq"):
        return _strip_names(pl.scan_parquet(p))
    if suffix in CSV_SUFFIXES:
        opts = csv_options(csv_columns)
        # En streaming las columnas enteras quedan como Float64: no se puede
        # volver a entero sin leer los datos, y para duplicados y validez da igual.
        return _strip_names(
            pl.scan_csv(
                p,
                schema_overrides=promoted_int_overrides(p, opts),
                **opts,  # type: ignore[arg-type]
            )
        )
    raise ValueError(
        f"modo streaming solo soporta CSV y Parquet, no {suffix!r}. "
        "Los demás lectores (Zeek, Suricata, PCAP) ya construyen el dataset "
        "completo en memoria, así que streamearlos no ahorraría nada."
    )


def _feature_cols(lf: pl.LazyFrame, label_col: str | None, split_col: str | None) -> list[str]:
    excluded = {label_col, split_col}
    return [c for c in lf.collect_schema().names() if c not in excluded and not c.startswith("__")]


def _dup_exact(
    lf: pl.LazyFrame,
    label_col: str | None,
    split_col: str | None,
    declared_roles: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Versión streaming de `dup.exact`: agrupa en vez de hashear fila a fila."""
    # Mismas columnas que `AuditContext.hash_cols`: sin los roles declarados.
    features = [c for c in _feature_cols(lf, label_col, split_col) if c not in declared_roles]
    if not features:
        raise CheckSkipped(_NO_FEATURES)
    group_cols = features + ([label_col] if label_col else [])

    total = lf.select(pl.len()).collect(engine="streaming").item()
    if total == 0:
        return []

    dupes = (
        lf.group_by(group_cols)
        .agg(pl.len().alias("n"))
        .filter(pl.col("n") > 1)
        .select(((pl.col("n") - 1).sum()).alias("n_extra"), pl.len().alias("n_groups"))
        .collect(engine="streaming")
    )
    n_extra = int(dupes["n_extra"][0] or 0)
    if n_extra == 0:
        return []

    ratio = n_extra / total
    severity = "high" if ratio >= 0.20 else "medium" if ratio >= 0.05 else "low"

    return [
        Finding(
            check_id="dup.exact",
            severity=severity,  # type: ignore[arg-type]
            title=f"{ratio:.2%} de las filas son duplicados exactos",
            description=(
                f"{n_extra:,} de {total:,} filas son copias de otra fila (mismas "
                "características y misma etiqueta), calculado por agrupación en modo "
                "streaming. Los duplicados inflan las métricas porque el modelo se "
                "evalúa sobre ejemplos que ya vio."
            ),
            metric={"n_duplicates": float(n_extra), "ratio": ratio},
            affected_rows=n_extra,
            examples=[],
            recommendation=(
                "Eliminar duplicados exactos antes de dividir en entrenamiento y "
                "prueba, o al menos verificar que no crucen entre splits."
            ),
            auto_fix="drop_duplicates",
        )
    ]


def _dup_cross_split(
    lf: pl.LazyFrame,
    label_col: str | None,
    split_col: str | None,
    declared_roles: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Versión streaming de `dup.cross_split`.

    Se salta con los mismos motivos que la versión normal: antes devolvía `[]`
    sin figurar como saltado, y el semáforo podía dar verde sin haber mirado
    el check más grave (AUDITORIA-1.0.md, COR-02).
    """
    if split_col is None:
        raise CheckSkipped("requiere 'split_col' (no fue especificado ni detectado)")
    features = [c for c in _feature_cols(lf, label_col, split_col) if c not in declared_roles]
    if not features:
        raise CheckSkipped(_NO_FEATURES)
    group_cols = features + ([label_col] if label_col else [])

    work = lf.drop_nulls(split_col)
    if work.select(pl.col(split_col).n_unique()).collect(engine="streaming").item() < 2:
        raise CheckSkipped(
            f"la columna '{split_col}' tiene un solo valor; no hay splits que comparar"
        )
    n_with_split = work.select(pl.len()).collect(engine="streaming").item()
    if n_with_split == 0:
        return []

    crossing = (
        work.group_by(group_cols)
        .agg(pl.col(split_col).n_unique().alias("n_splits"), pl.len().alias("n"))
        .filter(pl.col("n_splits") > 1)
        .select(pl.col("n").sum().alias("n_affected"), pl.len().alias("n_groups"))
        .collect(engine="streaming")
    )
    n_affected = int(crossing["n_affected"][0] or 0)
    if n_affected == 0:
        return []

    ratio = n_affected / n_with_split
    return [
        Finding(
            check_id="dup.cross_split",
            severity="critical",
            title=f"{n_affected:,} filas aparecen en más de un split",
            description=(
                f"{ratio:.2%} de las filas con split asignado tienen una copia en otro "
                f"split de '{split_col}' (calculado por agrupación en modo streaming). "
                "El modelo es evaluado con ejemplos idénticos a los que usó para "
                "entrenar, así que las métricas reportadas no son válidas."
            ),
            metric={"n_rows_affected": float(n_affected), "ratio": ratio},
            affected_rows=n_affected,
            examples=[],
            recommendation=(
                "Deduplicar antes de dividir, y dividir agrupando por sesión o por "
                "host en vez de al azar."
            ),
            auto_fix="drop_duplicates",
        )
    ]


def _validity_nan_inf(
    lf: pl.LazyFrame, label_col: str | None, split_col: str | None
) -> list[Finding]:
    """Versión streaming de `validity.nan_inf`, sin el agrupamiento por perfil
    compartido: eso requiere comparar máscaras fila a fila, que no es una
    agregación. Reporta cada columna afectada por separado."""
    schema = lf.collect_schema()
    numeric_cols = [c for c in _feature_cols(lf, label_col, split_col) if schema[c].is_numeric()]
    if not numeric_cols:
        return []

    total = lf.select(pl.len()).collect(engine="streaming").item()
    if total == 0:
        return []

    exprs = []
    for col in numeric_cols:
        exprs.append(pl.col(col).null_count().alias(f"{col}__null"))
        if schema[col].is_float():
            exprs.append(pl.col(col).is_nan().fill_null(False).sum().alias(f"{col}__nan"))
            exprs.append(pl.col(col).is_infinite().fill_null(False).sum().alias(f"{col}__inf"))
    row = lf.select(exprs).collect(engine="streaming").row(0, named=True)

    findings = []
    for col in numeric_cols:
        n_null = int(row[f"{col}__null"] or 0)
        n_nan = int(row.get(f"{col}__nan") or 0)
        n_inf = int(row.get(f"{col}__inf") or 0)
        n_bad = n_null + n_nan + n_inf
        if n_bad == 0:
            continue
        ratio = n_bad / total
        severity = "high" if n_inf > 0 or ratio >= 0.05 else "medium" if ratio >= 0.01 else "low"
        findings.append(
            Finding(
                check_id="validity.nan_inf",
                severity=severity,  # type: ignore[arg-type]
                title=f"La columna '{col}' tiene {n_bad:,} valores no finitos",
                description=(
                    f"{n_null:,} nulos, {n_nan:,} NaN y {n_inf:,} infinitos "
                    f"({ratio:.2%} de las filas), calculado en modo streaming."
                ),
                metric={
                    "null": float(n_null),
                    "nan": float(n_nan),
                    "inf": float(n_inf),
                    "ratio": ratio,
                },
                affected_rows=n_bad,
                examples=[],
                recommendation=(
                    f"Decidir explícitamente qué hacer con '{col}': imputar, acotar "
                    "los infinitos a un máximo, o eliminar la columna."
                ),
                auto_fix=None,
            )
        )
    return findings


def _validity_constant(
    lf: pl.LazyFrame, label_col: str | None, split_col: str | None
) -> list[Finding]:
    """Versión streaming de `validity.constant`."""
    features = _feature_cols(lf, label_col, split_col)
    if not features:
        return []

    row = (
        # Sin contar los nulos, igual que `validity.constant` en modo normal.
        lf.select([pl.col(c).drop_nulls().n_unique().alias(c) for c in features])
        .collect(engine="streaming")
        .row(0, named=True)
    )
    constant = [c for c in features if (row[c] or 0) <= 1]
    if not constant:
        return []

    return [
        Finding(
            check_id="validity.constant",
            severity="low",
            title=f"{len(constant)} columna(s) constante(s)",
            description=(
                "Estas columnas tienen un solo valor en todo el dataset (calculado en "
                f"modo streaming): {', '.join(constant[:20])}"
                + (" …" if len(constant) > 20 else "")
            ),
            metric={"n_constant_cols": float(len(constant))},
            affected_rows=0,
            examples=[{"columna": c} for c in constant[:10]],
            recommendation="Eliminarlas antes de entrenar.",
            auto_fix="drop_constant",
        )
    ]


def run_streaming_audit(
    path: str | Path,
    *,
    label_col: str | None = None,
    split_col: str | None = None,
    time_col: str | None = None,
    src_ip_col: str | None = None,
    dst_ip_col: str | None = None,
    version: str | None = None,
    seed: int = 42,
    profile: str | None = None,
) -> Report:
    """Corre los checks compatibles con streaming sobre ``path`` sin cargarlo
    entero en memoria. El resto de los checks del auditor quedan en
    ``report.skipped`` con el motivo, nunca en silencio.

    ``profile`` (R17) aporta la columna de etiqueta y, si el dataset se publica
    sin cabecera, los nombres de columna. Una columna explícita gana sobre el
    perfil.

    ``time_col``, ``src_ip_col`` y ``dst_ip_col`` (o los del perfil) son roles
    declarados: quedan fuera del hash de duplicados, igual que en
    ``AuditContext.hash_cols``, para que ambos modos den el mismo resultado.
    """
    if version is None:
        from vigia import __version__  # diferido: `vigia` importa este módulo

        version = __version__

    profile_data = load_profile(profile) if profile else {}
    roles = profile_data.get("column_roles", {})
    lf = _scan(path, profile_data.get("csv_columns"))
    schema = lf.collect_schema()

    # Misma detección por nombre que `vigia.load`, sobre el esquema (un
    # DataFrame vacío con las mismas columnas). Antes el modo streaming no
    # detectaba nada: `dup.exact` salía sin etiqueta y `dup.cross_split` ni
    # corría ni figuraba como saltado (AUDITORIA-1.0.md, COR-02).
    vacio = pl.DataFrame(schema=schema)
    label_col = label_col or roles.get("label_col") or detect_column(vacio, "label")
    split_col = split_col or roles.get("split_col") or detect_column(vacio, "split")
    declared = frozenset(
        c
        for c in (
            time_col or roles.get("time_col"),
            src_ip_col or roles.get("src_ip_col"),
            dst_ip_col or roles.get("dst_ip_col"),
        )
        if c
    )
    groups = profile_data.get("label_groups")
    if groups and label_col and label_col in schema.names():
        lf = lf.with_columns(label_groups_expr(label_col, groups).alias(label_col))
        schema = lf.collect_schema()
    n_cols = len(schema.names())
    n_rows = lf.select(pl.len()).collect(engine="streaming").item()

    report = Report(
        dataset_path=str(path),
        dataset_sha256="",  # el hash del archivo requeriría leerlo entero; se omite a propósito
        n_rows=n_rows,
        n_cols=n_cols,
        vigia_version=version,
        seed=seed,
    )

    corridas: dict[str, Callable[[], list[Finding]]] = {
        "dup.exact": lambda: _dup_exact(lf, label_col, split_col, declared),
        "dup.cross_split": lambda: _dup_cross_split(lf, label_col, split_col, declared),
        "validity.nan_inf": lambda: _validity_nan_inf(lf, label_col, split_col),
        "validity.constant": lambda: _validity_constant(lf, label_col, split_col),
    }
    for check_id, correr in corridas.items():
        try:
            report.findings.extend(correr())
        except CheckSkipped as exc:
            report.skipped[check_id] = str(exc)

    from vigia.core.registry import all_checks

    for check in all_checks("auditor"):
        if check.id not in STREAMING_CHECKS:
            report.skipped[check.id] = _NON_STREAMING_REASON

    return report
