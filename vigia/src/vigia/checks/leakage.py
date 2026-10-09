"""Checks de fuga entre entrenamiento y prueba (sección 8.4, requisito R6)."""

from __future__ import annotations

from typing import Any

import polars as pl

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register

#: Nombres de split que consideramos "prueba" y "entrenamiento". La validación
#: se agrupa con el entrenamiento: es parte de lo que el modelo ve al ajustarse,
#: así que una fuga de validación a prueba es igual de grave.
TEST_NAMES = {"test", "testing", "prueba", "eval", "evaluation", "holdout"}
TRAIN_NAMES = {
    "train",
    "training",
    "entrenamiento",
    "fit",
    "val",
    "valid",
    "validation",
    "validacion",
    "validación",
    "dev",
}


def _split_roles(values: list[str]) -> tuple[list[str], list[str]]:
    """Clasifica los valores de la columna de split en (entrenamiento, prueba)."""
    train = [v for v in values if v is not None and str(v).strip().lower() in TRAIN_NAMES]
    test = [v for v in values if v is not None and str(v).strip().lower() in TEST_NAMES]
    return train, test


def _unclassified(values: list[str]) -> list[str]:
    """Valores de split que no caen en ningún rol conocido.

    Sus filas quedan fuera del análisis, así que el hallazgo tiene que
    decirlo: un informe que calla lo que no miró induce a error.
    """
    known = TRAIN_NAMES | TEST_NAMES
    return sorted({str(v) for v in values if v is not None and str(v).strip().lower() not in known})


#: Formatos que se prueban cuando el usuario no indica uno. `None` deja que
#: Polars infiera ISO 8601 y variantes; los demás cubren lo que escriben los
#: extractores de flujos. d/m y m/d van los dos: elegir uno a ciegas es
#: justamente el error que hay que evitar (ver `_as_datetime`).
_TIME_FORMATS: tuple[str | None, ...] = (
    None,
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M",
    "%d/%m/%Y",
    "%m/%d/%Y",
)

#: Proporción máxima de valores no nulos que pueden quedar sin interpretar.
#: Una fila sin fecha no se puede ubicar antes ni después del corte, y si se
#: descarta en silencio puede ser justo la que filtra: con el 4 % del test
#: escrito en otro formato, el check daba "sin hallazgo" sobre una fuga real
#: (AUDITORIA-1.0.md, SCI-01). Una milésima tolera basura aislada sin dejar
#: pasar un bloque entero.
MAX_UNPARSED_RATIO = 0.001


def _distinto_orden(a: pl.Series, b: pl.Series) -> bool:
    """¿Hay dos filas que `a` ordena de una forma y `b` de la contraria?

    Ordenar por (a, b) y mirar si b quedó no decreciente: si no, existe una
    inversión. Los empates de `a` no cuentan como contradicción.
    """
    orden = pl.DataFrame({"a": a, "b": b}).sort("a", "b").get_column("b")
    return not orden.is_sorted()


def _as_datetime(s: pl.Series, time_format: str | None = None) -> pl.Series:
    """Convierte la columna de tiempo a datetime; numérica se trata como epoch.

    Antes se devolvía el primer formato que interpretara *algún* valor y el
    resto quedaba nulo y se descartaba sin aviso (SCI-01), y d/m se probaba
    antes que m/d, así que una fecha estadounidense con día <= 12 se leía al
    revés y daba un crítico falso (SCI-02). Ahora:

    - se elige el formato que interpreta más valores, y si aun así quedan sin
      interpretar más de `MAX_UNPARSED_RATIO`, se salta diciendo cuántos;
    - si dos formatos interpretan todo y ordenan las filas distinto, la
      columna es ambigua y se salta pidiendo el formato (``time_format``).

    Saltar es preferible a adivinar: un orden temporal inventado produce un
    número que se lee como un resultado.
    """
    if s.dtype in (pl.Datetime, pl.Date):
        return s
    if s.dtype.is_numeric():
        return s  # epoch: el orden relativo es lo único que nos importa

    n_valores = s.len() - s.null_count()
    if n_valores == 0:
        raise CheckSkipped("la columna de tiempo es completamente nula")

    formatos = (time_format,) if time_format else _TIME_FORMATS
    candidatos: list[tuple[str | None, pl.Series, int]] = []
    for fmt in formatos:
        try:
            parsed = s.str.to_datetime(format=fmt, strict=False)
        except Exception:
            continue
        candidatos.append((fmt, parsed, parsed.len() - parsed.null_count()))

    mejor = max((ok for _, _, ok in candidatos), default=0)
    if mejor == 0:
        detalle = f" con el formato {time_format!r}" if time_format else ""
        raise CheckSkipped(f"no se pudo interpretar la columna de tiempo como fecha{detalle}")

    sin_interpretar = n_valores - mejor
    if sin_interpretar / n_valores > MAX_UNPARSED_RATIO:
        raise CheckSkipped(
            f"{sin_interpretar:,} de {n_valores:,} valores de tiempo no se pudieron "
            "interpretar con un mismo formato; descartarlos podría esconder justo las "
            "filas que filtran. Indicá el formato con --time-format o normalizá la columna"
        )

    completos = [(fmt, p) for fmt, p, ok in candidatos if ok == mejor]
    base_fmt, base = completos[0]
    for fmt, p in completos[1:]:
        if _distinto_orden(base, p):
            raise CheckSkipped(
                f"el formato de la columna de tiempo es ambiguo: {base_fmt or 'inferido'!r} y "
                f"{fmt!r} interpretan todos los valores pero las ordenan distinto (día/mes "
                "contra mes/día). Indicá el formato con --time-format"
            )
    return base


@register
class TemporalLeakCheck:
    """`leak.temporal` — el conjunto de prueba ocurre antes del de entrenamiento.

    Si los splits se solapan en el tiempo (o peor, la prueba es anterior), la
    evaluación no mide la capacidad de detectar ataques futuros, que es
    justamente lo que hace un NIDS en producción (Pendlebury et al., TESSERACT).
    """

    id = "leak.temporal"
    name = "Fuga temporal entre entrenamiento y prueba"
    category = "leakage"
    applies_to = {"flows"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("split_col", "time_col")
        assert ctx.split_col is not None and ctx.time_col is not None

        # Los roles se deciden sobre todos los valores del split, antes de mirar
        # el tiempo: si no, un split cuyas filas no tienen fecha desaparecía y
        # el motivo decía "no se reconocen splits", que era falso.
        splits = ctx.df.get_column(ctx.split_col).cast(pl.Utf8)
        split_values = splits.drop_nulls().unique().to_list()
        train_names, test_names = _split_roles(split_values)
        if not train_names or not test_names:
            raise CheckSkipped(
                f"no se reconocen splits de entrenamiento y prueba en '{ctx.split_col}'"
            )
        ignored = _unclassified(split_values)

        ts = _as_datetime(ctx.df.get_column(ctx.time_col), ctx.option("time_format", None))
        con_rol = pl.DataFrame({"split": splits, "ts": ts}).filter(
            pl.col("split").is_in(train_names + test_names)
        )
        # Filas sin tiempo (nulas de origen): no se pueden ubicar, y el
        # hallazgo tiene que decir cuántas quedaron fuera.
        n_sin_tiempo = int(con_rol.get_column("ts").null_count())
        work = con_rol.drop_nulls()
        if not work.is_empty() and n_sin_tiempo / con_rol.height > MAX_UNPARSED_RATIO:
            # Con más que eso, "sin hallazgo" no se puede afirmar: las filas sin
            # fecha pueden ser justo las que filtran.
            raise CheckSkipped(
                f"{n_sin_tiempo:,} de {con_rol.height:,} filas de entrenamiento o prueba "
                "no tienen tiempo; no se puede afirmar que el split respete el orden temporal"
            )

        train = work.filter(pl.col("split").is_in(train_names)).get_column("ts")
        test = work.filter(pl.col("split").is_in(test_names)).get_column("ts")
        if train.is_empty() or test.is_empty():
            lado = "entrenamiento" if train.is_empty() else "prueba"
            raise CheckSkipped(f"las filas de {lado} están todas sin tiempo")

        # Los extremos son escalares comparables entre sí (datetime o epoch
        # numérico): `_as_datetime` ya descartó cualquier otro tipo.
        train_min: Any = train.min()
        train_max: Any = train.max()
        test_min: Any = test.min()
        test_max: Any = test.max()

        # Filas de prueba que NO son posteriores al entrenamiento. La comparación
        # es `<=`, no `<`: una fila de prueba simultánea al último instante de
        # entrenamiento también es solape. Con `<` se escapaban los datasets de
        # granularidad gruesa (CIC-IDS2017 marca al segundo y miles de flujos
        # comparten el mismo instante), que es justo donde más duele.
        n_before = int((test <= train_max).sum())
        overlap_ratio = n_before / test.len()

        if overlap_ratio == 0:
            return []

        if test_max <= train_min:
            severity, kind = (
                "critical",
                "El conjunto de prueba es enteramente anterior al de entrenamiento.",
            )
        elif test_min >= train_min and test_max <= train_max:
            severity, kind = (
                "critical",
                "El conjunto de prueba está contenido dentro del periodo de "
                "entrenamiento: el split no respeta el orden temporal en absoluto.",
            )
        elif overlap_ratio >= 0.5:
            severity, kind = "critical", "Los conjuntos se solapan en el tiempo casi por completo."
        else:
            severity, kind = "high", "Los conjuntos se solapan parcialmente en el tiempo."

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{overlap_ratio:.1%} de las filas de prueba son anteriores al fin del entrenamiento",
                description=(
                    f"{kind} Entrenamiento: {train_min} a {train_max}. "
                    f"Prueba: {test_min} a {test_max}. "
                    "Evaluar sin respetar el orden temporal infla los resultados: el modelo "
                    "'predice' ataques que ya ocurrieron durante su propio entrenamiento."
                    + (
                        f" Se ignoraron los splits {', '.join(repr(s) for s in ignored)}, "
                        "que no se reconocen como entrenamiento ni prueba."
                        if ignored
                        else ""
                    )
                    + (
                        f" {n_sin_tiempo:,} filas sin tiempo quedaron fuera del cálculo."
                        if n_sin_tiempo
                        else ""
                    )
                ),
                metric={
                    "overlap_ratio": overlap_ratio,
                    "n_test_rows_before_train_end": float(n_before),
                    "n_sin_tiempo": float(n_sin_tiempo),
                },
                affected_rows=n_before,
                examples=[
                    {"split": "train", "desde": str(train_min), "hasta": str(train_max)},
                    {"split": "test", "desde": str(test_min), "hasta": str(test_max)},
                ],
                recommendation=(
                    "Rehacer el split por corte temporal: entrenar con el periodo anterior y "
                    "evaluar con el posterior (ver `fix.temporal_split` y TESSERACT)."
                ),
                auto_fix="temporal_split",
            )
        ]


@register
class SessionLeakCheck:
    """`leak.session` — flujos de la misma conexión repartidos entre splits.

    CICFlowMeter parte una conexión larga en varios flujos por timeout. Si esos
    trozos caen a ambos lados del split, el modelo ve en prueba la continuación
    de algo que ya estudió en entrenamiento: no es una conexión nueva, es la
    misma. Es una fuga más fina que `leak.host` y sobrevive a dividir por IP.
    """

    id = "leak.session"
    name = "Fuga por sesión entre splits"
    category = "leakage"
    applies_to = {"flows"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("split_col", "src_ip_col", "dst_ip_col")
        assert ctx.split_col is not None

        # La 5-tupla identifica la conexión. Sin puertos quedaría un par de
        # hosts, que es lo que ya mira `leak.host`: no aportaría nada nuevo.
        tuple_cols = [
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
        # Las cinco: con una sola ausente (p. ej. el puerto de origen) dos
        # "sesiones" son pares host-servicio, no conexiones, y el check daba
        # crítico por algo que `leak.host` ya mira (AUDITORIA-1.0.md, COR-04).
        if len(tuple_cols) < 5:
            raise CheckSkipped(
                "requiere la 5-tupla (IPs, puertos y protocolo) para identificar la sesión"
            )

        splits = ctx.df.get_column(ctx.split_col).cast(pl.Utf8)
        train_names, test_names = _split_roles(splits.unique().to_list())
        if not train_names or not test_names:
            raise CheckSkipped(
                f"no se reconocen splits de entrenamiento y prueba en '{ctx.split_col}'"
            )

        work = ctx.df.select(tuple_cols).with_columns(splits.alias("__split"))
        work = work.with_columns(
            pl.concat_str(
                [pl.col(c).cast(pl.Utf8).fill_null("\x00") for c in tuple_cols], separator="\x1f"
            ).alias("__sid")
        ).drop_nulls("__split")

        train_ids = set(
            work.filter(pl.col("__split").is_in(train_names)).get_column("__sid").unique().to_list()
        )
        test_rows = work.filter(pl.col("__split").is_in(test_names))
        if not train_ids or test_rows.is_empty():
            raise CheckSkipped("uno de los splits quedó vacío")

        shared = train_ids & set(test_rows.get_column("__sid").unique().to_list())
        if not shared:
            return []

        n_test_affected = int(test_rows.filter(pl.col("__sid").is_in(list(shared))).height)
        ratio = n_test_affected / test_rows.height
        severity = "critical" if ratio >= 0.10 else "high"

        ejemplos = (
            work.filter(pl.col("__sid").is_in(list(shared)[:10]))
            .select(tuple_cols)
            .unique()
            .head(10)
            .to_dicts()
        )

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{len(shared):,} sesiones aparecen en entrenamiento y en prueba",
                description=(
                    f"El {ratio:.1%} de las filas de prueba ({n_test_affected:,}) pertenecen "
                    f"a conexiones (misma 5-tupla) que también están en entrenamiento. "
                    "El extractor parte las conexiones largas en varios flujos por timeout, "
                    "así que el modelo evalúa la continuación de un tráfico que ya vio. "
                    "Dividir por host no arregla esto: los trozos comparten IP igual."
                ),
                metric={
                    "n_sesiones_compartidas": float(len(shared)),
                    "test_rows_ratio": ratio,
                    "n_filas_prueba": float(n_test_affected),
                },
                affected_rows=n_test_affected,
                examples=ejemplos,
                recommendation=(
                    "Rehacer el split agrupando por la 5-tupla: todos los flujos de una "
                    "misma conexión deben caer del mismo lado (ver `fix.group_split`)."
                ),
                auto_fix="group_split",
            )
        ]


@register
class HostLeakCheck:
    """`leak.host` — el mismo host aparece en entrenamiento y en prueba.

    En un dataset de laboratorio el atacante usa siempre las mismas máquinas.
    Si esas IPs están en ambos splits, el modelo memoriza el host y la métrica
    de prueba no dice nada sobre un atacante nuevo.
    """

    id = "leak.host"
    name = "Fuga por host entre splits"
    category = "leakage"
    applies_to = {"flows"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("split_col")
        assert ctx.split_col is not None

        ip_cols = [c for c in (ctx.src_ip_col, ctx.dst_ip_col) if c is not None]
        if not ip_cols:
            raise CheckSkipped("no se identificó ninguna columna de IP (src_ip / dst_ip)")

        splits = ctx.df.get_column(ctx.split_col).cast(pl.Utf8)
        split_values = splits.unique().to_list()
        train_names, test_names = _split_roles(split_values)
        if not train_names or not test_names:
            raise CheckSkipped(
                f"no se reconocen splits de entrenamiento y prueba en '{ctx.split_col}'"
            )
        ignored = _unclassified(split_values)

        findings: list[Finding] = []
        for col in ip_cols:
            work = pl.DataFrame({"split": splits, "host": ctx.df.get_column(col).cast(pl.Utf8)})
            work = work.drop_nulls()
            if work.is_empty():
                continue

            train_hosts = set(
                work.filter(pl.col("split").is_in(train_names))
                .get_column("host")
                .unique()
                .to_list()
            )
            test_rows = work.filter(pl.col("split").is_in(test_names))
            if not train_hosts or test_rows.is_empty():
                continue

            test_hosts = set(test_rows.get_column("host").unique().to_list())
            shared = train_hosts & test_hosts
            if not shared:
                continue

            n_test_affected = int(test_rows.filter(pl.col("host").is_in(list(shared))).height)
            ratio = n_test_affected / test_rows.height
            host_ratio = len(shared) / len(test_hosts)

            severity = "critical" if ratio >= 0.5 else "high"

            findings.append(
                Finding(
                    check_id=self.id,
                    severity=severity,  # type: ignore[arg-type]
                    title=(
                        f"{len(shared):,} host(s) de '{col}' aparecen en entrenamiento y en prueba"
                    ),
                    description=(
                        f"El {ratio:.1%} de las filas de prueba ({n_test_affected:,}) provienen "
                        f"de hosts que el modelo ya vio durante el entrenamiento, y el "
                        f"{host_ratio:.1%} de los hosts de prueba no son nuevos. El modelo puede "
                        "memorizar la dirección en vez de aprender el comportamiento del ataque."
                        + (
                            f" Se ignoraron los splits {', '.join(repr(s) for s in ignored)}, "
                            "que no se reconocen como entrenamiento ni prueba."
                            if ignored
                            else ""
                        )
                    ),
                    metric={
                        "n_shared_hosts": float(len(shared)),
                        "test_rows_ratio": ratio,
                        "shared_host_ratio": host_ratio,
                    },
                    affected_rows=n_test_affected,
                    examples=[{"columna": col, "host": h} for h in sorted(shared)[:10]],
                    recommendation=(
                        "Rehacer el split agrupando por host: todas las filas de una misma IP "
                        "deben caer del mismo lado (ver `fix.group_split`). Y considerar "
                        "excluir la columna de IP de las características."
                    ),
                    auto_fix="group_split",
                )
            )

        return findings
