"""Checks de atajos (sección 8.5, requisito R5).

Un atajo es una columna que permite acertar la etiqueta sin aprender el
fenómeno: la IP del atacante del laboratorio, un puerto efímero, un timestamp.
El modelo luce perfecto en el laboratorio y falla en una red real.
"""

from __future__ import annotations

import re
from typing import cast

import polars as pl

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register

#: Patrones de nombres que casi nunca deberían ser características. Los cortos
#: llevan borde de palabra: sin él `uid` marcaba "ruido" y "guide", y `flow.?id`
#: marcaba "flow_idle_time", que entonces salían de los modelos auxiliares y
#: `drop_identifiers` las borraba (AUDITORIA-1.0.md, COR-13).
IDENTIFIER_PATTERNS: tuple[str, ...] = (
    r"\bip\b",
    r"ipaddr",
    r"address",
    r"\bid\b",
    r"\bflow.?id\b",
    r"\buid\b",
    r"timestamp",
    r"\bts\b",
    r"datetime",
    r"source.?file",
    r"\bmac\b",
)


def _looks_like_identifier(name: str) -> bool:
    norm = re.sub(r"[^a-z0-9]", " ", name.lower())
    return any(re.search(p, norm) for p in IDENTIFIER_PATTERNS)


def _balanced_accuracy_single_feature(values: pl.Series, labels: pl.Series) -> tuple[float, int]:
    """Exactitud balanceada de la regla "predecir la clase mayoritaria de cada valor".

    Es el techo de lo que un árbol de decisión sin profundidad limitada puede
    lograr usando solo esta columna, y se calcula con un ``group_by`` en vez de
    entrenar un modelo: la señal es la misma y corre sobre millones de filas.

    Devuelve (exactitud balanceada, cardinalidad de la columna).
    """
    df = pl.DataFrame({"v": values.cast(pl.Utf8).fill_null("\x00"), "y": labels.cast(pl.Utf8)})

    # Para cada valor de la columna, la clase mayoritaria y cuántas filas acierta.
    per_value = (
        df.group_by("v", "y")
        .agg(pl.len().alias("n"))
        .sort("n", descending=True)
        .group_by("v")
        .agg(pl.col("y").first().alias("pred"), pl.col("n").first().alias("n_correct"))
    )

    predicted = df.join(per_value, on="v", how="left")
    # Aciertos por clase real / total por clase real, promediado sobre clases.
    per_class = (
        predicted.with_columns((pl.col("y") == pl.col("pred")).alias("ok"))
        .group_by("y")
        .agg(pl.col("ok").mean().alias("recall"))
    )
    # `mean()` de una columna de booleanos es float, o None si no hay filas.
    mean_recall = per_class.get_column("recall").mean()
    bal_acc = float(cast("float", mean_recall)) if mean_recall is not None else 0.0
    return bal_acc, int(df.get_column("v").n_unique())


def _quantile_bins(s: pl.Series, n_bins: int) -> pl.Series:
    """Tramos por cuantil de una columna numérica; nulos, NaN e infinitos aparte.

    Los cuantiles repetidos (una columna con mucha masa en un valor) se unen en
    vez de fallar: un tramo con todos los ceros es lo que hay que ver.
    """
    f = s.cast(pl.Float64)
    f = pl.Series(
        f.name,
        f.to_frame()
        .select(pl.when(pl.col(f.name).is_finite()).then(pl.col(f.name)).otherwise(None))
        .to_series(),
    )
    return f.qcut(n_bins, allow_duplicates=True).cast(pl.Utf8)


@register
class SingleFeatureShortcutCheck:
    """`shortcut.single_feature` — una sola columna predice la etiqueta demasiado bien."""

    id = "shortcut.single_feature"
    name = "Atajo por una sola columna"
    category = "shortcuts"
    applies_to = {"flows", "tabular"}

    #: Umbral de exactitud balanceada por encima del cual una columna es sospechosa.
    DEFAULT_THRESHOLD = 0.95
    #: Una columna con muchos valores distintos acierta por memorización, no por
    #: señal: agrupar por valor deja casi una fila por grupo y la exactitud da 1.0
    #: para cualquier columna continua. Por encima de esta proporción de valores
    #: únicos la métrica no es evidencia de atajo, así que el caso le corresponde
    #: a `shortcut.identifier`, no a este check.
    MAX_CARDINALITY_RATIO = 0.3
    #: Además, un grupo de una sola fila nunca es evidencia. Exigimos que en
    #: promedio cada valor cubra al menos estas filas.
    MIN_ROWS_PER_VALUE = 3.0
    #: Tramos por cuantil para las columnas numéricas de alta cardinalidad. Con
    #: 50, cada tramo es el 2 % de las filas: suficiente para ver un umbral que
    #: separa clases, y con bastantes filas por tramo para que una columna de
    #: ruido no acierte por memorización (sobre ruido continuo da ~0,5).
    #: Límite: una clase más rara que un tramo queda en minoría en todos y no
    #: se ve; el hallazgo es una cota inferior en ese caso.
    MAX_BINS = 50
    #: Filas mínimas por tramo, para datasets chicos.
    MIN_ROWS_PER_BIN = 20

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        assert ctx.label_col is not None

        labels = ctx.df.get_column(ctx.label_col)
        if labels.n_unique() < 2:
            raise CheckSkipped("la columna de etiqueta tiene una sola clase")

        threshold = float(ctx.option("shortcut_threshold", self.DEFAULT_THRESHOLD))
        n = ctx.n_rows
        findings: list[Finding] = []

        for col in ctx.feature_cols:
            s = ctx.df.get_column(col)
            # Demasiados valores distintos: agrupar por valor deja una o dos
            # filas por grupo y el acierto es memorización, no señal. Antes la
            # columna se descartaba y "lo cubría `shortcut.identifier`", que
            # solo mira el nombre: un umbral perfecto sobre una tasa o una
            # duración no lo reportaba nadie (AUDITORIA-1.0.md, SCI-05). Si la
            # columna es numérica se discretiza por cuantiles y se aplica la
            # misma regla a los tramos; si no lo es (IPs, ids de texto), no hay
            # orden que discretizar y sigue a cargo de `shortcut.identifier`.
            cardinality = s.n_unique()
            n_tramos = 0
            if cardinality > max(2, n * self.MAX_CARDINALITY_RATIO) or (
                cardinality and n / cardinality < self.MIN_ROWS_PER_VALUE
            ):
                if not s.dtype.is_numeric():
                    continue
                n_tramos = max(2, min(self.MAX_BINS, n // self.MIN_ROWS_PER_BIN))
                s = _quantile_bins(s, n_tramos)

            bal_acc, cardinality = _balanced_accuracy_single_feature(s, labels)
            if bal_acc < threshold:
                continue
            rows_per_value = n / cardinality if cardinality else 0.0

            is_identifier = _looks_like_identifier(col)
            why = (
                "El nombre indica además que es un identificador (IP, ID de flujo, "
                "timestamp), no una característica del comportamiento del tráfico."
                if is_identifier
                else "Vale la pena revisar si esta columna refleja el ataque real o un "
                "artefacto del laboratorio donde se generó el dataset."
            )

            findings.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title=f"La columna '{col}' predice la etiqueta con {bal_acc:.1%} de exactitud balanceada",
                    description=(
                        f"Usando únicamente '{col}' se alcanza una exactitud balanceada de "
                        f"{bal_acc:.3f} (umbral: {threshold}). {why} Un modelo entrenado con "
                        "esta columna puede lucir casi perfecto sin haber aprendido nada "
                        "sobre los ataques."
                        + (
                            f" La columna es continua: se midió sobre {n_tramos} tramos por "
                            "cuantil, que es lo que un árbol aprende con un par de cortes."
                            if n_tramos
                            else ""
                        )
                    ),
                    metric={
                        "balanced_accuracy": bal_acc,
                        "threshold": threshold,
                        "cardinality": float(cardinality),
                        "rows_per_value": rows_per_value,
                        "n_tramos": float(n_tramos),
                    },
                    affected_rows=n,
                    examples=(ctx.df.select(col, ctx.label_col).head(10).to_dicts()),
                    recommendation=(
                        f"Eliminar '{col}' de las características, o dividir los datos por "
                        "host/sesión para que la columna deje de ser informativa. Volver a "
                        "medir el rendimiento sin ella: ese es el número real."
                    ),
                    auto_fix="drop_identifiers" if is_identifier else None,
                )
            )

        return findings


@register
class IdentifierColumnCheck:
    """`shortcut.identifier` — columnas identificadoras usadas como características."""

    id = "shortcut.identifier"
    name = "Columnas identificadoras entre las características"
    category = "shortcuts"
    applies_to = {"flows", "tabular"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        # Las columnas de rol que el usuario declaró (tiempo, IPs) no se marcan:
        # ya dijo que son metadatos. Si una de ellas delata la etiqueta, la
        # encuentran `shortcut.single_feature` y los checks de fuga.
        suspects = [
            c for c in ctx.feature_cols if c not in ctx.declared_roles and _looks_like_identifier(c)
        ]
        if not suspects:
            return []

        return [
            Finding(
                check_id=self.id,
                severity="high",
                title=f"{len(suspects)} columna(s) identificadora(s) presentes como características",
                description=(
                    "Estas columnas identifican al host, al flujo o al momento de la captura "
                    "en vez de describir el comportamiento del tráfico: "
                    f"{', '.join(suspects[:20])}"
                    + (" …" if len(suspects) > 20 else "")
                    + ". En un dataset de laboratorio el atacante siempre usa las mismas IPs, "
                    "así que el modelo aprende la IP y no el ataque."
                ),
                metric={"n_identifier_cols": float(len(suspects))},
                affected_rows=0,
                examples=[{"columna": c} for c in suspects[:10]],
                recommendation=(
                    "Excluirlas del entrenamiento. Si se necesitan para agrupar el split "
                    "(por host o por sesión), usarlas solo para eso."
                ),
                auto_fix="drop_identifiers",
            )
        ]
