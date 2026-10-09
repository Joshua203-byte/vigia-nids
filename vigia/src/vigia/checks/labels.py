"""Checks de etiquetas (sección 8.3, requisitos R4 y R7).

La etiqueta es lo único que el modelo no puede verificar por su cuenta: si
está mal, todo lo demás da igual. Estos checks buscan etiquetas contradictorias,
inconsistentes por escritura y clases tan pequeñas que su métrica no significa
nada.
"""

from __future__ import annotations

import re

import polars as pl

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register


@register
class LabelConflictCheck:
    """`labels.conflict` — mismas características, distinta etiqueta.

    Dos filas idénticas con etiquetas distintas no pueden ser ambas correctas.
    Es el ruido de etiqueta más fácil de probar: no hace falta un modelo, basta
    agrupar por el hash de las características.
    """

    id = "labels.conflict"
    name = "Conflictos de etiqueta"
    category = "labels"
    applies_to = {"flows", "tabular"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        assert ctx.label_col is not None
        if ctx.n_rows == 0:
            return []
        if not ctx.hash_cols:
            # Sin características todas las filas son idénticas por definición,
            # así que cualquier diferencia de etiqueta sería un "conflicto"
            # trivial que no dice nada sobre el dataset.
            raise CheckSkipped("el dataset no tiene columnas de características")

        # Una fila sin etiqueta no contradice a nadie: no hay dos etiquetas que
        # elegir. Si entrara al grupo, `n_unique` la contaba como una etiqueta
        # más y el `join` de abajo fallaba con TypeError, así que el check
        # entero terminaba como "error interno" (AUDITORIA-1.0.md, COR-03).
        work = pl.DataFrame(
            {
                "h": ctx.row_hash,
                "label": ctx.df.get_column(ctx.label_col).cast(pl.Utf8),
            }
        ).drop_nulls("label")
        # Grupos de filas idénticas que no se ponen de acuerdo en la etiqueta.
        conflicts = (
            work.group_by("h")
            .agg(
                pl.col("label").n_unique().alias("n_labels"),
                pl.len().alias("n_rows"),
                pl.col("label").unique().sort().alias("labels"),
            )
            .filter(pl.col("n_labels") > 1)
            .sort("n_rows", descending=True)
        )
        if conflicts.is_empty():
            return []

        n_groups = conflicts.height
        n_affected = int(conflicts.get_column("n_rows").sum())
        ratio = n_affected / ctx.n_rows

        # Los pares de etiquetas que más se confunden entre sí.
        pairs: dict[str, int] = {}
        for row in conflicts.head(2000).iter_rows(named=True):
            key = " / ".join(row["labels"])
            pairs[key] = pairs.get(key, 0) + int(row["n_rows"])
        top_pairs = sorted(pairs.items(), key=lambda kv: -kv[1])[:10]

        severity = "critical" if ratio >= 0.01 else "high"

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{n_groups:,} grupos de filas idénticas tienen etiquetas distintas",
                description=(
                    f"{n_affected:,} filas ({ratio:.2%}) tienen exactamente las mismas "
                    "características que otra fila pero una etiqueta diferente. No pueden "
                    "ser ambas correctas: o la etiqueta está mal, o a las características "
                    "les falta la información que distingue los dos casos. En cualquiera "
                    "de los dos escenarios el modelo no puede aprender a separarlos y el "
                    "techo de su exactitud queda fijado por este ruido."
                ),
                metric={
                    "n_conflict_groups": float(n_groups),
                    "n_rows_affected": float(n_affected),
                    "ratio": ratio,
                },
                affected_rows=n_affected,
                examples=[{"etiquetas_en_conflicto": k, "filas": v} for k, v in top_pairs],
                recommendation=(
                    "Revisar los pares de etiquetas que más se confunden. Si el conflicto "
                    "es entre 'BENIGN' y un ataque, suele indicar que la ventana de tiempo "
                    "del etiquetado no coincide con el ataque real."
                ),
                auto_fix=None,
            )
        ]


@register
class LabelTaxonomyCheck:
    """`labels.taxonomy` — la misma clase escrita de varias formas.

    'DoS Hulk', 'DoS-Hulk' y 'dos hulk' son la misma clase para un analista y
    tres clases distintas para el modelo, que reparte los ejemplos entre ellas
    y reporta métricas por separado.
    """

    id = "labels.taxonomy"
    name = "Etiquetas inconsistentes en su escritura"
    category = "labels"
    applies_to = {"flows", "tabular"}

    @staticmethod
    def _normalize(label: str) -> str:
        """Minúsculas, sin signos ni espacios repetidos."""
        return re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        assert ctx.label_col is not None

        counts = (
            ctx.df.get_column(ctx.label_col)
            .cast(pl.Utf8)
            .drop_nulls()
            .value_counts(sort=True)
            .rows()
        )
        groups: dict[str, list[tuple[str, int]]] = {}
        for label, n in counts:
            groups.setdefault(self._normalize(str(label)), []).append((str(label), int(n)))

        colisiones = {k: v for k, v in groups.items() if len(v) > 1}
        if not colisiones:
            return []

        n_affected = sum(n for variants in colisiones.values() for _, n in variants)

        return [
            Finding(
                check_id=self.id,
                severity="high",
                title=f"{len(colisiones)} clase(s) escritas de más de una forma",
                description=(
                    "Estas etiquetas son la misma clase escrita distinto. El modelo las "
                    "trata como clases separadas: reparte los ejemplos entre ellas, "
                    "reporta una métrica por cada variante y ninguna refleja el "
                    "rendimiento real sobre ese ataque."
                ),
                metric={
                    "n_clases_afectadas": float(len(colisiones)),
                    "n_filas": float(n_affected),
                },
                affected_rows=n_affected,
                examples=[
                    {
                        "clase": k,
                        "variantes": ", ".join(f"{lbl!r} ({n:,})" for lbl, n in v),
                    }
                    for k, v in list(colisiones.items())[:10]
                ],
                recommendation=(
                    "Unificar la escritura antes de entrenar y antes de reportar "
                    "métricas por clase."
                ),
                auto_fix="normalize_labels",
            )
        ]


@register
class LabelImbalanceCheck:
    """`labels.imbalance` — clases con tan pocos ejemplos que su métrica no dice nada.

    Un recall de 0.50 sobre 11 ejemplos (Heartbleed en CIC-IDS2017) no distingue
    un modelo bueno de uno malo: cada ejemplo vale 9 puntos porcentuales.
    """

    id = "labels.imbalance"
    name = "Clases demasiado pequeñas para evaluarlas"
    category = "labels"
    applies_to = {"flows", "tabular"}

    #: Por debajo de esta cantidad de ejemplos, la métrica de una clase depende
    #: de tan pocas filas que su intervalo de confianza cubre casi todo el rango.
    MIN_EXAMPLES = 100
    #: En un dataset chico el umbral absoluto no significa nada: con 120 filas
    #: en total, "menos de 100 ejemplos" describe a casi todas las clases y el
    #: hallazgo no informa. El umbral efectivo nunca pasa de esta fracción del
    #: dataset, para que el check hable de clases desproporcionadamente raras
    #: y no del tamaño del archivo.
    MAX_THRESHOLD_RATIO = 0.10

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        assert ctx.label_col is not None
        if ctx.n_rows == 0:
            return []

        counts = (
            ctx.df.get_column(ctx.label_col)
            .cast(pl.Utf8)
            .drop_nulls()
            .value_counts(sort=True)
            .rows()
        )
        if len(counts) < 2:
            raise CheckSkipped("la columna de etiqueta tiene una sola clase")

        threshold = int(ctx.option("min_class_examples", self.MIN_EXAMPLES))
        threshold = min(threshold, int(ctx.n_rows * self.MAX_THRESHOLD_RATIO))
        if threshold < 2:
            return []
        pequenas = [(str(lbl), int(n)) for lbl, n in counts if n < threshold]
        if not pequenas:
            return []

        mayor = int(counts[0][1])
        menor = min(n for _, n in pequenas)
        ratio_desbalance = mayor / menor if menor else float("inf")

        return [
            Finding(
                check_id=self.id,
                severity="medium",
                title=f"{len(pequenas)} clase(s) con menos de {threshold} ejemplos",
                description=(
                    f"La clase más grande tiene {mayor:,} ejemplos y la más chica {menor:,} "
                    f"(proporción {ratio_desbalance:,.0f} a 1). Con tan pocos ejemplos, el "
                    "recall de esas clases se mueve muchos puntos por cada fila acertada o "
                    "fallada, así que no permite comparar modelos ni afirmar que el ataque "
                    "se detecta."
                ),
                metric={
                    "n_clases_pequenas": float(len(pequenas)),
                    "min_ejemplos": float(menor),
                    "max_ejemplos": float(mayor),
                    "ratio_desbalance": ratio_desbalance,
                },
                affected_rows=sum(n for _, n in pequenas),
                examples=[{"clase": lbl, "ejemplos": n} for lbl, n in pequenas[:10]],
                recommendation=(
                    "Reportar el número de ejemplos junto a la métrica de cada clase, y "
                    "acompañar el recall con un intervalo de confianza. No presentar el "
                    "promedio macro sin aclarar qué clases lo sostienen."
                ),
                auto_fix=None,
            )
        ]
