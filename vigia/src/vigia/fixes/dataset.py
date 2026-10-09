"""Correcciones que actúan sobre las filas y columnas del dataset."""

from __future__ import annotations

import polars as pl

from vigia.checks.labels import LabelTaxonomyCheck
from vigia.checks.shortcuts import _looks_like_identifier
from vigia.core.context import AuditContext
from vigia.fixes.base import FixNotApplicable, FixResult, _result, register_fix


@register_fix("drop_duplicates")
def drop_duplicates(ctx: AuditContext) -> FixResult:
    """Elimina filas idénticas, conservando la primera aparición.

    Se deduplica sobre características **y** etiqueta: dos filas con las mismas
    características y etiquetas distintas no son duplicados sino un conflicto
    de etiqueta, y borrar una al azar elegiría una etiqueta sin fundamento.
    Ese caso lo reporta `labels.conflict` y lo resuelve una persona.
    """
    keys = ctx.hash_cols + ([ctx.label_col] if ctx.label_col else [])
    if not keys:
        raise FixNotApplicable("el dataset no tiene columnas sobre las que deduplicar")

    df = ctx.df.unique(subset=keys, keep="first", maintain_order=True)
    removed = ctx.n_rows - df.height
    return _result(
        ctx,
        "drop_duplicates",
        df,
        f"{removed:,} filas duplicadas eliminadas, {df.height:,} conservadas",
        {"criterio": "características + etiqueta", "n_columnas_clave": len(keys)},
    )


@register_fix("drop_identifiers")
def drop_identifiers(ctx: AuditContext) -> FixResult:
    """Quita las columnas identificadoras (IPs, IDs de flujo, timestamps).

    Son las que permiten al modelo memorizar el laboratorio en vez de aprender
    el ataque. La columna de split se conserva aunque su nombre lo parezca: es
    metadato de la partición, no una característica.
    """
    protected = {ctx.label_col, ctx.split_col}
    to_drop = [c for c in ctx.df.columns if c not in protected and _looks_like_identifier(c)]
    if not to_drop:
        raise FixNotApplicable("no se encontraron columnas identificadoras")

    df = ctx.df.drop(to_drop)
    return _result(
        ctx,
        "drop_identifiers",
        df,
        f"{len(to_drop)} columnas identificadoras eliminadas: {', '.join(to_drop[:10])}",
        {"columnas_eliminadas": to_drop},
    )


@register_fix("drop_constant")
def drop_constant(ctx: AuditContext) -> FixResult:
    """Quita las columnas con un solo valor distinto: no aportan información."""
    protected = {ctx.label_col, ctx.split_col}
    # Mismo criterio que `validity.constant`: los nulos no cuentan como valor.
    to_drop = [
        c
        for c in ctx.feature_cols
        if c not in protected and ctx.df.get_column(c).drop_nulls().n_unique() <= 1
    ]
    if not to_drop:
        raise FixNotApplicable("no se encontraron columnas constantes")

    df = ctx.df.drop(to_drop)
    return _result(
        ctx,
        "drop_constant",
        df,
        f"{len(to_drop)} columnas constantes eliminadas: {', '.join(to_drop[:10])}",
        {"columnas_eliminadas": to_drop},
    )


@register_fix("strip_column_names")
def strip_column_names(ctx: AuditContext) -> FixResult:
    """Quita los espacios sobrantes de los nombres de columna."""
    mapping = {c: c.strip() for c in ctx.df.columns if c != c.strip()}
    if not mapping:
        raise FixNotApplicable("ningún nombre de columna tiene espacios sobrantes")

    df = ctx.df.rename(mapping)
    return _result(
        ctx,
        "strip_column_names",
        df,
        f"{len(mapping)} nombres de columna normalizados",
        {"renombradas": mapping},
    )


@register_fix("normalize_labels")
def normalize_labels(ctx: AuditContext) -> FixResult:
    """Unifica las etiquetas que son la misma clase escrita distinto.

    De cada grupo de variantes se conserva la forma más frecuente, que suele
    ser la escritura canónica del dataset.
    """
    if ctx.label_col is None:
        raise FixNotApplicable("requiere una columna de etiqueta")

    counts = (
        ctx.df.get_column(ctx.label_col).cast(pl.Utf8).drop_nulls().value_counts(sort=True).rows()
    )
    groups: dict[str, list[tuple[str, int]]] = {}
    for label, n in counts:
        groups.setdefault(LabelTaxonomyCheck._normalize(str(label)), []).append(
            (str(label), int(n))
        )

    # De cada grupo con más de una variante, la más frecuente gana.
    mapping = {
        variant: variants[0][0]
        for variants in groups.values()
        if len(variants) > 1
        for variant, _ in variants[1:]
    }
    if not mapping:
        raise FixNotApplicable("las etiquetas ya son consistentes")

    df = ctx.df.with_columns(
        pl.col(ctx.label_col).cast(pl.Utf8).replace(mapping).alias(ctx.label_col)
    )
    return _result(
        ctx,
        "normalize_labels",
        df,
        f"{len(mapping)} variantes de etiqueta unificadas",
        {"mapeo": mapping},
    )


@register_fix("quarantine_noise")
def quarantine_noise(ctx: AuditContext) -> FixResult:
    """Aparta las filas con etiqueta sospechosa en vez de borrarlas.

    Nunca se eliminan: una etiqueta dudosa puede ser correcta y el modelo
    auxiliar equivocado. Quedan en `FixResult.quarantined` para que una
    persona las revise y decida.
    """
    from vigia.checks.label_noise import LabelNoiseCheck

    findings = LabelNoiseCheck().run(ctx)
    if not findings or not findings[0].row_indices:
        raise FixNotApplicable("no se detectaron etiquetas sospechosas")

    idx = findings[0].row_indices
    idx_name = "__idx"
    work = ctx.df.with_row_index(idx_name)
    sospechosa = pl.col(idx_name).is_in(idx)

    limpio = work.filter(~sospechosa).drop(idx_name)
    cuarentena = work.filter(sospechosa).drop(idx_name)

    # En un dataset grande el check trabaja sobre una muestra, así que lo
    # apartado es lo que alcanzó a revisar: decirlo evita que se lea como
    # "estas son todas las etiquetas dudosas del dataset".
    n_eval = int(findings[0].metric["n_evaluadas"])
    parcial = n_eval < ctx.n_rows

    return _result(
        ctx,
        "quarantine_noise",
        limpio,
        f"{cuarentena.height:,} filas con etiqueta sospechosa apartadas para revisión"
        + (f" (estimado sobre una muestra de {n_eval:,} filas)" if parcial else ""),
        {
            "n_apartadas": cuarentena.height,
            "n_evaluadas": n_eval,
            "muestreado": parcial,
            "nota": "las filas no se borran: quedan en FixResult.quarantined",
        },
        quarantined=cuarentena,
    )
