"""Checks de duplicados (sección 8.2, requisito R2)."""

from __future__ import annotations

import random

import polars as pl

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register


@register
class ExactDuplicateCheck:
    """`dup.exact` — filas idénticas.

    Los ataques repetitivos (DoS) generan flujos casi idénticos por diseño, así
    que un porcentaje alto no siempre es un error del dataset; lo grave es que
    esos duplicados crucen entre entrenamiento y prueba (ver `dup.cross_split`).
    """

    id = "dup.exact"
    name = "Filas duplicadas exactas"
    category = "duplicates"
    applies_to = {"flows", "tabular"}
    #: Además del suyo, este check emite hallazgos con este id (ver `_per_class`).
    also_emits = ("dup.class_ratio",)

    def run(self, ctx: AuditContext) -> list[Finding]:
        n = ctx.n_rows
        if n == 0:
            return []
        if not ctx.hash_cols:
            # Sin características, todas las filas de una misma clase serían
            # "duplicados" por definición. No es información sobre el dataset.
            raise CheckSkipped("el dataset no tiene columnas de características")

        h = ctx.full_row_hash
        n_unique = int(h.n_unique())
        n_dupes = n - n_unique
        if n_dupes == 0:
            return []

        ratio = n_dupes / n
        if ratio >= 0.20:
            severity = "high"
        elif ratio >= 0.05:
            severity = "medium"
        else:
            severity = "low"

        # Filas cuyo hash aparece más de una vez.
        dup_mask = h.is_duplicated()

        findings = [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{ratio:.2%} de las filas son duplicados exactos",
                description=(
                    f"{n_dupes:,} de {n:,} filas son copias de otra fila (mismas "
                    f"características y misma etiqueta). Quedan {n_unique:,} filas únicas. "
                    "Los duplicados inflan las métricas porque el modelo se evalúa sobre "
                    "ejemplos que ya vio."
                ),
                metric={
                    "n_duplicates": float(n_dupes),
                    "ratio": ratio,
                    "n_unique": float(n_unique),
                },
                affected_rows=n_dupes,
                examples=ctx.examples_from(dup_mask),
                recommendation=(
                    "Eliminar duplicados exactos antes de dividir en entrenamiento y "
                    "prueba, o al menos verificar que no crucen entre splits."
                ),
                auto_fix="drop_duplicates",
            )
        ]

        findings.extend(self._per_class(ctx, h))
        return findings

    def _per_class(self, ctx: AuditContext, h: pl.Series) -> list[Finding]:
        """`dup.class_ratio`: clases que son mayoritariamente duplicados."""
        if ctx.label_col is None:
            return []

        per_class = (
            ctx.df.select(pl.col(ctx.label_col).alias("label"))
            .with_columns(h.alias("h"))
            .group_by("label")
            .agg(
                pl.len().alias("n"),
                pl.col("h").n_unique().alias("n_unique"),
            )
            .with_columns(((pl.col("n") - pl.col("n_unique")) / pl.col("n")).alias("dup_ratio"))
            .filter((pl.col("dup_ratio") >= 0.5) & (pl.col("n") >= 10))
            .sort("dup_ratio", descending=True)
        )
        if per_class.is_empty():
            return []

        rows = per_class.to_dicts()
        return [
            Finding(
                check_id="dup.class_ratio",
                severity="medium",
                title=f"{len(rows)} clase(s) formada(s) mayoritariamente por duplicados",
                description=(
                    "En estas clases más de la mitad de las filas son copias. El número "
                    "efectivo de ejemplos distintos es mucho menor que el conteo de filas, "
                    "así que el recall reportado para ellas no es confiable."
                ),
                metric={
                    r["label"] if r["label"] is not None else "null": r["dup_ratio"]
                    for r in rows[:20]
                },
                affected_rows=int(sum(r["n"] - r["n_unique"] for r in rows)),
                examples=[
                    {
                        "clase": r["label"],
                        "filas": r["n"],
                        "unicas": r["n_unique"],
                        "duplicados": f"{r['dup_ratio']:.1%}",
                    }
                    for r in rows[:10]
                ],
                recommendation=(
                    "Reportar el número de ejemplos únicos por clase junto con las "
                    "métricas, y deduplicar antes de dividir los datos."
                ),
                auto_fix="drop_duplicates",
            )
        ]


@register
class CrossSplitDuplicateCheck:
    """`dup.cross_split` — la misma fila en entrenamiento y en prueba.

    Es el caso crítico: el modelo memoriza y la prueba mide memorización, no
    generalización.
    """

    id = "dup.cross_split"
    name = "Duplicados que cruzan entre splits"
    category = "duplicates"
    applies_to = {"flows", "tabular"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("split_col")
        assert ctx.split_col is not None
        if not ctx.hash_cols:
            raise CheckSkipped("el dataset no tiene columnas de características")

        work = ctx.df.select(pl.col(ctx.split_col).alias("split")).with_columns(
            ctx.full_row_hash.alias("h")
        )
        # Una fila sin split no pertenece a ningún conjunto, así que no puede
        # "cruzar" entre dos. Si no se descartaran, `n_unique` contaría el nulo
        # como un split más y una fila duplicada entre 'train' y un nulo se
        # reportaría como crítica sin serlo.
        n_unassigned = int(work.get_column("split").null_count())
        work = work.drop_nulls("split")
        splits = work.get_column("split").unique().to_list()
        if len(splits) < 2:
            raise CheckSkipped(
                f"la columna '{ctx.split_col}' tiene un solo valor; no hay splits que comparar"
            )

        # Hashes presentes en más de un split.
        crossing = (
            work.group_by("h")
            .agg(pl.col("split").n_unique().alias("n_splits"), pl.len().alias("n"))
            .filter(pl.col("n_splits") > 1)
        )
        if crossing.is_empty():
            return []

        crossing_hashes = crossing.get_column("h").to_list()
        # La máscara se arma contra el dataframe completo, no contra `work`:
        # `examples_from` filtra `ctx.df` y las longitudes deben coincidir. Las
        # filas sin split quedan fuera porque su hash solo cruza si además
        # aparece en dos splits reales.
        assigned = ctx.df.get_column(ctx.split_col).is_not_null()
        mask = ctx.full_row_hash.is_in(crossing_hashes) & assigned
        n_affected = int(mask.sum())
        # La proporción se mide sobre las filas que sí tienen split asignado.
        ratio = n_affected / work.height

        return [
            Finding(
                check_id=self.id,
                severity="critical",
                title=f"{n_affected:,} filas aparecen en más de un split",
                description=(
                    f"{int(crossing.height):,} filas distintas están repetidas en dos o más "
                    f"splits de '{ctx.split_col}' ({ratio:.2%} de las filas con split "
                    "asignado). El modelo es evaluado con ejemplos idénticos a los que usó "
                    "para entrenar, así que las métricas reportadas no son válidas."
                    + (
                        f" ({n_unassigned:,} filas sin split se excluyeron del cálculo.)"
                        if n_unassigned
                        else ""
                    )
                ),
                metric={
                    "n_rows_affected": float(n_affected),
                    "n_distinct_rows": float(crossing.height),
                    "ratio": ratio,
                    "n_unassigned": float(n_unassigned),
                },
                affected_rows=n_affected,
                examples=ctx.examples_from(mask),
                recommendation=(
                    "Deduplicar antes de dividir, y dividir agrupando por sesión o por "
                    "host en vez de al azar (ver `leak.host` y `fix.group_split`)."
                ),
                auto_fix="drop_duplicates",
            )
        ]


def _row_shingles(df: pl.DataFrame, columns: list[str]) -> list[set[str]]:
    """Convierte cada fila en un conjunto de tokens ``"columna=valor"``.

    Los numéricos se redondean a 4 decimales: sin esto, dos flujos que
    difieren solo en ruido de punto flotante (ej. una tasa de bytes/s
    calculada con distinta precisión) nunca comparten ningún token y el
    Jaccard entre ellos da 0 aunque sean, a efectos prácticos, la misma fila.
    """
    work = df.select(columns)
    rounded = work.with_columns(
        pl.col(c).round(4) if work.schema[c].is_numeric() else pl.col(c) for c in columns
    )
    rows = rounded.cast(pl.Utf8).fill_null("\x00").to_dicts()
    return [{f"{k}={v}" for k, v in row.items()} for row in rows]


@register
class NearDuplicateCheck:
    """`dup.near` — filas casi idénticas que `dup.exact` no puede ver.

    Dos flujos que difieren en una sola columna (una tasa recalculada con
    distinta precisión, un contador con off-by-one del extractor) tienen
    hashes distintos y `dup.exact` los deja pasar, pero siguen siendo
    prácticamente el mismo ejemplo para un modelo.
    """

    id = "dup.near"
    name = "Filas casi duplicadas"
    category = "duplicates"
    applies_to = {"flows", "tabular"}

    #: Similitud de Jaccard mínima entre dos filas para considerarlas casi
    #: duplicadas. Por debajo de esto, dos flujos del mismo tipo de tráfico
    #: (ej. dos "BENIGN" cualquiera) empiezan a solaparse por azar, no por
    #: ser copias.
    DEFAULT_THRESHOLD = 0.9
    #: Cantidad de funciones hash de cada MinHash: a más permutaciones, la
    #: similitud estimada se acerca más al Jaccard real, a costa de memoria
    #: y tiempo. 128 es el valor por defecto de datasketch y el que usan la
    #: mayoría de los benchmarks publicados de LSH para texto/tabular.
    NUM_PERM = 128
    #: Sin esto, un dataset con muchas filas casi idénticas por diseño (DoS
    #: repetitivo, igual que en `dup.exact`) generaría cientos de miles de
    #: pares y el check tardaría minutos por algo que ya se sabe. Es una
    #: salvaguarda de costo, no una opinión sobre si el dataset está bien.
    #: Por encima de este tamaño se trabaja sobre una muestra al azar, y el
    #: resultado es una cota inferior (ver `run`).
    MAX_ROWS = 200_000

    def run(self, ctx: AuditContext) -> list[Finding]:
        n = ctx.n_rows
        if n < 2:
            return []
        if not ctx.hash_cols:
            raise CheckSkipped("el dataset no tiene columnas de características")
        try:
            from datasketch import MinHash, MinHashLSH
        except ImportError as exc:  # pragma: no cover - depende del entorno
            raise CheckSkipped("requiere datasketch: pip install 'vigia-nids[ml]'") from exc

        threshold = float(ctx.option("near_duplicate_threshold", self.DEFAULT_THRESHOLD))
        # Con num_perm=128, MinHashLSH necesita al menos 2 bandas; a partir de
        # ~0.99 el cálculo interno de bandas/filas colapsa a 1 y lanza
        # ValueError. Mejor un CheckSkipped claro que ese traceback.
        if threshold >= 0.99:
            raise CheckSkipped(
                f"near_duplicate_threshold={threshold} es demasiado alto para num_perm="
                f"{self.NUM_PERM} (máximo práctico: 0.98)"
            )

        # Las repeticiones exactas quedan fuera: ya tienen su hallazgo en
        # dup.exact. Pero solo las repeticiones: la primera aparición de cada
        # fila se queda como representante. Antes se excluían *todas* las
        # copias y el casi-duplicado de una fila repetida quedaba sin pareja,
        # así que agregar una copia exacta hacía desaparecer el hallazgo: el
        # caso típico del DoS repetitivo (AUDITORIA-1.0.md, SCI-08).
        es_repeticion = ~ctx.full_row_hash.is_first_distinct()

        # Sobre MAX_ROWS filas se mira una muestra al azar: el costo del LSH
        # crece con las filas y el objetivo es estimar cuánto hay, no
        # enumerarlo. Dos copias solo se ven si las dos caen en la muestra, así
        # que lo que se reporta es una cota inferior de lo que hay.
        sampled = n > self.MAX_ROWS
        if sampled:
            positions = sorted(random.Random(ctx.seed).sample(range(n), self.MAX_ROWS))
        else:
            positions = list(range(n))
        n_eval = len(positions)

        candidate_idx = [i for i in positions if not es_repeticion[i]]
        if len(candidate_idx) < 2:
            return []

        # Los tokens solo se arman para las filas candidatas: sobre una
        # muestra de un dataset de millones, armarlos para todas sería el
        # costo que la muestra quiere evitar.
        shingle_sets = _row_shingles(ctx.df[candidate_idx], ctx.hash_cols)

        # `MinHash.bulk` calcula las mismas firmas que `update` token por token,
        # pero reutiliza la inicializacion de las permutaciones en vez de
        # regenerarlas por fila: 8 veces mas rapido (20.000 filas de 44
        # columnas: 4 s contra 34 s). Con ``update`` este check tardaba 13
        # minutos en 175.000 filas.
        signatures = MinHash.bulk(
            [[token.encode("utf-8") for token in tokens] for tokens in shingle_sets],
            num_perm=self.NUM_PERM,
        )
        lsh = MinHashLSH(threshold=threshold, num_perm=self.NUM_PERM)
        minhashes: dict[int, MinHash] = dict(zip(candidate_idx, signatures, strict=True))
        with lsh.insertion_session() as session:
            for i, mh in minhashes.items():
                session.insert(str(i), mh)

        # Unión-find liviana: agrupamos filas conectadas por al menos un par
        # sobre el umbral, para reportar clusters en vez de pares sueltos
        # (miles de pares casi-idénticos suelen ser el mismo puñado de filas
        # repetidas, no miles de problemas distintos).
        parent = {i: i for i in candidate_idx}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        seen_pairs: set[tuple[int, int]] = set()
        n_pairs = 0
        for i in candidate_idx:
            for match in lsh.query(minhashes[i]):
                j = int(match)
                if j == i:
                    continue
                pair = (min(i, j), max(i, j))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                n_pairs += 1
                union(i, j)

        if n_pairs == 0:
            return []

        clusters: dict[int, list[int]] = {}
        for i in candidate_idx:
            clusters.setdefault(find(i), []).append(i)
        clusters = {root: rows for root, rows in clusters.items() if len(rows) > 1}

        if not clusters:
            return []

        n_affected = sum(len(rows) for rows in clusters.values())
        ratio = n_affected / n_eval
        if ratio >= 0.10:
            severity = "high"
        elif ratio >= 0.02:
            severity = "medium"
        else:
            severity = "low"

        affected_idx = {idx for rows in clusters.values() for idx in rows}
        nota_muestra = (
            f" Se revisó una muestra al azar de {n_eval:,} de {n:,} filas: dos copias solo "
            "se ven si las dos caen en la muestra, así que es una cota inferior de lo que hay."
            if sampled
            else ""
        )

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{n_affected:,} filas son casi duplicadas de otra ({len(clusters)} grupo(s))",
                description=(
                    f"{n_affected:,} filas tienen una similitud de Jaccard de al menos "
                    f"{threshold:.0%} con otra fila del dataset, sin ser duplicados exactos "
                    "(esos ya los reporta `dup.exact`). Suele venir de ruido de precisión "
                    "numérica o de contadores con pequeñas variaciones entre capturas del "
                    "mismo evento." + nota_muestra
                ),
                metric={
                    "n_affected": float(n_affected),
                    "ratio": ratio,
                    "n_evaluated": float(n_eval),
                    "n_clusters": float(len(clusters)),
                    "threshold": threshold,
                },
                affected_rows=n_affected,
                examples=ctx.df[sorted(affected_idx)[:10]].to_dicts(),
                recommendation=(
                    "Revisar si estas filas son el mismo evento capturado dos veces; si lo "
                    "son, tratarlas como duplicados para dividir train/test."
                ),
                auto_fix=None,
            )
        ]
