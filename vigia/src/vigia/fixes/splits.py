"""Correcciones que rehacen la partición entre entrenamiento y prueba."""

from __future__ import annotations

import polars as pl

from vigia.checks.leakage import _as_datetime
from vigia.core.context import AuditContext, CheckSkipped
from vigia.fixes.base import FixNotApplicable, FixResult, _result, register_fix

#: Proporción de entrenamiento por defecto en las particiones rehechas.
DEFAULT_TRAIN_RATIO = 0.7


@register_fix("temporal_split")
def temporal_split(ctx: AuditContext) -> FixResult:
    """Rehace el split por corte temporal: entrena con el pasado, evalúa con el futuro.

    Es lo que hace un NIDS en producción, y lo que mide TESSERACT: detectar
    ataques que todavía no ocurrieron. Un split aleatorio sobre datos con orden
    temporal mide otra cosa —memorización— y da números mucho mejores.
    """
    if ctx.time_col is None:
        raise FixNotApplicable("requiere una columna de tiempo (--time-col)")

    ratio = float(ctx.option("train_ratio", DEFAULT_TRAIN_RATIO))
    if not 0 < ratio < 1:
        raise FixNotApplicable(f"train_ratio debe estar entre 0 y 1, no {ratio}")

    # El mismo parser que `leak.temporal`: si allá la columna es ambigua o no se
    # interpreta, acá tampoco se puede cortar por tiempo sin inventar el orden.
    try:
        ts = _as_datetime(ctx.df.get_column(ctx.time_col), ctx.option("time_format", None))
    except CheckSkipped as exc:
        raise FixNotApplicable(str(exc)) from exc

    # El corte es el cuantil del tiempo: todo lo anterior entrena.
    cutoff = ts.drop_nulls().quantile(ratio, interpolation="nearest")
    if cutoff is None:
        raise FixNotApplicable("no se pudo calcular el punto de corte temporal")

    # Una fila sin tiempo no está ni antes ni después del corte. Antes caía en
    # el `otherwise` y terminaba en "test", donde `leak.temporal` no la ve
    # (AUDITORIA-1.0.md, SCI-09). Queda sin split, que es lo honesto: ningún
    # check la cuenta de un lado ni del otro, y el resumen lo dice.
    split_col = ctx.split_col or "split"
    ts_col = pl.Series(ts)
    df = ctx.df.with_columns(
        pl.when(ts_col.is_null())
        .then(pl.lit(None, dtype=pl.Utf8))
        .when(ts_col <= cutoff)
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias(split_col)
    )

    n_train = int(df.filter(pl.col(split_col) == "train").height)
    n_test = int(df.filter(pl.col(split_col) == "test").height)
    n_sin_tiempo = df.height - n_train - n_test
    return _result(
        ctx,
        "temporal_split",
        df,
        f"split rehecho por tiempo: {n_train:,} entrenamiento / {n_test:,} prueba, "
        f"corte en {cutoff}"
        + (f"; {n_sin_tiempo:,} filas sin tiempo quedaron sin split" if n_sin_tiempo else ""),
        {
            "corte": str(cutoff),
            "n_train": n_train,
            "n_test": n_test,
            "n_sin_tiempo": n_sin_tiempo,
            "columna": split_col,
        },
    )


@register_fix("group_split")
def group_split(ctx: AuditContext) -> FixResult:
    """Rehace el split agrupando, de modo que un grupo no se reparta entre lados.

    Agrupa por la 5-tupla si está disponible, y si no por host. Todas las filas
    del mismo grupo caen del mismo lado, así que el modelo no puede evaluarse
    con la continuación de algo que ya vio.
    """
    # `group_by="host"` agrupa solo por IP de origen: elimina también la fuga
    # por host, a costa de repartir conexiones entre lados. Con la 5-tupla
    # (por defecto) ocurre lo contrario. No se puede tener las dos cosas.
    modo = str(ctx.option("group_by", "session"))
    if modo == "host":
        group_cols = [c for c in (ctx.src_ip_col,) if c is not None]
    else:
        group_cols = [
            c
            for c in (
                ctx.src_ip_col,
                ctx.dst_ip_col,
                ctx.src_port_col,
                ctx.dst_port_col,
                ctx.protocol_col,
            )
            if c is not None
        ]
    if not group_cols:
        raise FixNotApplicable("requiere al menos una columna de IP para agrupar (5-tupla o host)")

    ratio = float(ctx.option("train_ratio", DEFAULT_TRAIN_RATIO))
    if not 0 < ratio < 1:
        raise FixNotApplicable(f"train_ratio debe estar entre 0 y 1, no {ratio}")

    gid = "__group"
    work = ctx.df.with_columns(
        pl.concat_str(
            [pl.col(c).cast(pl.Utf8).fill_null("\x00") for c in group_cols],
            separator="\x1f",
        ).alias(gid)
    )

    # Los grupos se reparten al azar pero enteros. La semilla del contexto hace
    # que la partición sea reproducible.
    groups = work.get_column(gid).unique().to_frame(gid)
    groups = groups.sample(fraction=1.0, shuffle=True, seed=ctx.seed)
    n_train_groups = max(1, int(groups.height * ratio))
    train_groups = set(groups.head(n_train_groups).get_column(gid).to_list())

    split_col = ctx.split_col or "split"
    df = work.with_columns(
        pl.when(pl.col(gid).is_in(list(train_groups)))
        .then(pl.lit("train"))
        .otherwise(pl.lit("test"))
        .alias(split_col)
    ).drop(gid)

    n_train = int(df.filter(pl.col(split_col) == "train").height)
    n_test = df.height - n_train

    # Agrupar por la 5-tupla separa las conexiones, pero un host que aparece en
    # muchas de ellas —un servidor, un DNS— sigue estando a ambos lados. No es
    # un defecto de la corrección: es que no se puede tener a la vez un split
    # por conexión y un split por host. Decirlo evita que alguien crea que
    # `leak.host` quedó resuelto cuando no lo está.
    hosts_compartidos: dict[str, int] = {}
    for col in (ctx.src_ip_col, ctx.dst_ip_col):
        if col is None:
            continue
        en_train = set(df.filter(pl.col(split_col) == "train").get_column(col).unique().to_list())
        en_test = set(df.filter(pl.col(split_col) == "test").get_column(col).unique().to_list())
        if compartidos := en_train & en_test:
            hosts_compartidos[col] = len(compartidos)

    aviso = ""
    if hosts_compartidos:
        detalle = ", ".join(f"{n} en '{c}'" for c, n in hosts_compartidos.items())
        aviso = (
            f". Quedan hosts en ambos lados ({detalle}): son extremos que participan "
            "en muchas conexiones y no pueden asignarse a un solo lado sin romper el "
            "agrupamiento por sesión. Para eliminar también la fuga por host hay que "
            "agrupar solo por IP, a costa de perder conexiones enteras"
        )

    return _result(
        ctx,
        "group_split",
        df,
        f"split rehecho por grupo ({', '.join(group_cols)}): "
        f"{n_train:,} entrenamiento / {n_test:,} prueba, {groups.height:,} grupos" + aviso,
        {
            "columnas_de_grupo": group_cols,
            "n_grupos": groups.height,
            "n_train": n_train,
            "n_test": n_test,
            "columna": split_col,
            "hosts_aun_compartidos": hosts_compartidos,
        },
    )
