"""Checks de validez básica (sección 8.1)."""

from __future__ import annotations

import math
from typing import cast

import polars as pl

from vigia.core.context import AuditContext
from vigia.core.findings import Finding
from vigia.core.registry import register


@register
class NanInfCheck:
    """`validity.nan_inf` — valores NaN o infinitos.

    CIC-IDS2017 los tiene en las columnas de tasas (``Flow Bytes/s``,
    ``Flow Packets/s``) porque divide entre una duración de cero.
    """

    id = "validity.nan_inf"
    name = "Valores NaN o infinitos"
    category = "validity"
    applies_to = {"flows", "tabular"}

    #: Cuando varias columnas tienen exactamente el mismo recuento de valores
    #: no finitos, casi siempre es un solo problema: filas truncadas o sin
    #: etiqueta que dejaron toda la fila vacía. En CIC-IDS2017 son 80 columnas
    #: con 288.602 nulos cada una. Emitir un hallazgo por columna convierte el
    #: reporte en una pared de texto que oculta todo lo demás, así que a partir
    #: de este número se agrupan en uno solo.
    GROUP_THRESHOLD = 3

    def run(self, ctx: AuditContext) -> list[Finding]:
        n = ctx.n_rows
        if n == 0:
            return []

        # (nulos, nan, inf) -> columnas que comparten ese perfil exacto.
        by_profile: dict[tuple[int, int, int], list[str]] = {}
        for col in ctx.numeric_cols:
            s = ctx.df.get_column(col)
            n_null = int(s.null_count())
            # NaN e infinito solo existen en columnas de punto flotante.
            if s.dtype.is_float():
                n_nan = int(s.is_nan().fill_null(False).sum())
                n_inf = int(s.is_infinite().fill_null(False).sum())
            else:
                n_nan = n_inf = 0

            if n_null + n_nan + n_inf == 0:
                continue
            by_profile.setdefault((n_null, n_nan, n_inf), []).append(col)

        findings: list[Finding] = []
        for (n_null, n_nan, n_inf), cols in sorted(
            by_profile.items(), key=lambda kv: -(kv[0][0] + kv[0][1] + kv[0][2])
        ):
            n_bad = n_null + n_nan + n_inf
            ratio = n_bad / n
            # Un infinito rompe el entrenamiento; un nulo aislado es higiene.
            if n_inf > 0 or ratio >= 0.05:
                severity = "high"
            elif ratio >= 0.01:
                severity = "medium"
            else:
                severity = "low"

            agrupado = len(cols) >= self.GROUP_THRESHOLD
            if agrupado:
                title = (
                    f"{len(cols)} columnas comparten {n_bad:,} valores no finitos "
                    "en las mismas filas"
                )
                extra = (
                    f" El recuento idéntico en {len(cols)} columnas apunta a una causa "
                    "común: filas truncadas o sin etiqueta que quedaron vacías, no un "
                    "problema independiente de cada columna. Columnas: "
                    f"{', '.join(cols[:15])}" + (" …" if len(cols) > 15 else "")
                )
                recommendation = (
                    "Buscar primero la causa compartida: revisar si esas filas están "
                    "truncadas o sin etiquetar y si deben descartarse enteras. Imputar "
                    "columna por columna aquí sería tapar el problema."
                )
            else:
                title = f"La columna '{cols[0]}' tiene {n_bad:,} valores no finitos"
                extra = ""
                recommendation = (
                    f"Decidir explícitamente qué hacer con '{cols[0]}': imputar, acotar "
                    "los infinitos a un máximo, o eliminar la columna. No dejar que "
                    "el modelo reciba infinitos."
                )

            # La evidencia se toma de la primera columna del grupo: por
            # construcción todas fallan en las mismas filas.
            s0 = ctx.df.get_column(cols[0])
            bad_mask = s0.is_null()
            if s0.dtype.is_float():
                bad_mask = (
                    bad_mask | s0.is_nan().fill_null(False) | s0.is_infinite().fill_null(False)
                )

            findings.append(
                Finding(
                    check_id=self.id,
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=(
                        f"{n_null:,} nulos, {n_nan:,} NaN y {n_inf:,} infinitos "
                        f"({ratio:.2%} de las filas). Los infinitos suelen venir de "
                        "dividir entre una duración de cero al calcular tasas." + extra
                    ),
                    metric={
                        "null": float(n_null),
                        "nan": float(n_nan),
                        "inf": float(n_inf),
                        "ratio": ratio,
                        "n_columns": float(len(cols)),
                    },
                    affected_rows=n_bad,
                    examples=ctx.examples_from(bad_mask),
                    recommendation=recommendation,
                    auto_fix=None,
                )
            )
        return findings


@register
class ConstantCheck:
    """`validity.constant` — columnas con un solo valor distinto."""

    id = "validity.constant"
    name = "Columnas constantes"
    category = "validity"
    applies_to = {"flows", "tabular"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        if ctx.n_rows == 0:
            return []

        constant: list[str] = []
        for col in ctx.feature_cols:
            s = ctx.df.get_column(col)
            # Cardinalidad 1 ignorando nulos, o columna enteramente nula.
            # `n_unique` cuenta el nulo como un valor: [7, 7, 7, None] daba 2 y
            # la columna no se reportaba (AUDITORIA-1.0.md, COR-12).
            if s.drop_nulls().n_unique() <= 1:
                constant.append(col)

        if not constant:
            return []

        return [
            Finding(
                check_id=self.id,
                severity="low",
                title=f"{len(constant)} columna(s) constante(s)",
                description=(
                    "Estas columnas tienen un solo valor en todo el dataset, así que no "
                    "aportan información al modelo pero sí ocupan memoria y ruido en la "
                    f"importancia de características: {', '.join(constant[:20])}"
                    + (" …" if len(constant) > 20 else "")
                ),
                metric={"n_constant_cols": float(len(constant))},
                affected_rows=0,
                examples=[{"columna": c} for c in constant[:10]],
                recommendation="Eliminarlas antes de entrenar.",
                auto_fix="drop_constant",
            )
        ]


@register
class ColumnHygieneCheck:
    """`validity.column_names` — nombres de columna con espacios o duplicados."""

    id = "validity.column_names"
    name = "Higiene de nombres de columna"
    category = "validity"
    applies_to = {"flows", "tabular"}

    def run(self, ctx: AuditContext) -> list[Finding]:
        cols = ctx.df.columns
        with_space = [c for c in cols if c != c.strip()]
        stripped = [c.strip() for c in cols]
        dupes = sorted({c for c in stripped if stripped.count(c) > 1})

        findings: list[Finding] = []
        if with_space:
            findings.append(
                Finding(
                    check_id=self.id,
                    severity="low",
                    title=f"{len(with_space)} columna(s) con espacios en el nombre",
                    description=(
                        "Los nombres traen espacios al inicio o al final, lo que provoca "
                        "errores silenciosos al seleccionar columnas por nombre "
                        f"(típico de los CSV de CICFlowMeter): {', '.join(repr(c) for c in with_space[:10])}"
                    ),
                    metric={"n_cols": float(len(with_space))},
                    affected_rows=0,
                    examples=[{"columna": c} for c in with_space[:10]],
                    recommendation="Aplicar `.strip()` a los nombres al cargar el dataset.",
                    auto_fix="strip_column_names",
                )
            )
        if dupes:
            findings.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=f"{len(dupes)} nombre(s) de columna duplicado(s) tras normalizar",
                    description=(
                        "Dos o más columnas quedan con el mismo nombre al quitar espacios, "
                        f"lo que hace ambigua cualquier selección: {', '.join(dupes[:10])}"
                    ),
                    metric={"n_dupes": float(len(dupes))},
                    affected_rows=0,
                    examples=[{"columna": c} for c in dupes[:10]],
                    recommendation="Renombrar explícitamente antes de entrenar.",
                    auto_fix=None,
                )
            )
        return findings


@register
class ImpossibleValuesCheck:
    """`validity.impossible` — valores que el dominio de red no permite."""

    id = "validity.impossible"
    name = "Valores imposibles según el dominio"
    category = "validity"
    applies_to = {"flows"}

    #: (patrón en el nombre normalizado, mínimo permitido, máximo permitido)
    RULES: tuple[tuple[str, float, float], ...] = (
        ("port", 0, 65535),
        ("duration", 0, math.inf),
        ("byte", 0, math.inf),
        ("packet", 0, math.inf),
        ("pkt", 0, math.inf),
        ("len", 0, math.inf),
    )

    #: Columnas donde ``-1`` no es un valor medido sino "no aplica".
    #: CICFlowMeter lo usa en las ventanas TCP iniciales cuando el flujo no
    #: llegó a establecer una: en CIC-IDS2017 eso es el 42 % de las filas, así
    #: que tratarlo como valor imposible sepulta los desbordamientos reales
    #: bajo cientos de miles de falsos positivos.
    SENTINEL_PATTERNS: tuple[str, ...] = ("init_win_bytes", "init fwd win", "init bwd win")
    SENTINEL_VALUE = -1.0

    def _uses_sentinel(self, norm: str) -> bool:
        return any(p in norm for p in self.SENTINEL_PATTERNS)

    def run(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for col in ctx.numeric_cols:
            norm = col.lower()
            for pattern, lo, hi in self.RULES:
                if pattern not in norm:
                    continue
                # Se compara en Float64: una columna Int8/Int16 (p. ej. un
                # indicador 0/1 llamado `is_sm_ips_ports`) no puede representar
                # el limite 65535 y polars lanza OverflowError.
                s = ctx.df.get_column(col)
                sf = s.cast(pl.Float64)
                mask = (sf < lo) | (sf > hi) if hi != math.inf else (sf < lo)
                if self._uses_sentinel(norm):
                    mask = mask & (sf != self.SENTINEL_VALUE)
                mask = mask.fill_null(False)
                n_bad = int(mask.sum())
                if n_bad == 0:
                    break

                # La columna es numérica (viene de `numeric_cols`); min/max solo
                # son None si está enteramente vacía.
                raw_min, raw_max = s.min(), s.max()
                observed_min = float(cast("float", raw_min)) if raw_min is not None else 0.0
                observed_max = float(cast("float", raw_max)) if raw_max is not None else 0.0

                findings.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=f"La columna '{col}' tiene {n_bad:,} valores fuera de rango",
                        description=(
                            f"Se esperaban valores entre {lo} y "
                            f"{'sin limite' if hi == math.inf else hi} por el significado de la "
                            "columna; hay valores fuera de ese rango. Suele indicar un "
                            "error del extractor de flujos o un desalineamiento de columnas."
                        ),
                        metric={
                            "n_invalid": float(n_bad),
                            "min_allowed": lo,
                            # Sin cota superior la clave se omite: un `-1.0` de
                            # centinela se lee como "el máximo permitido es -1",
                            # que no significa nada para bytes o paquetes.
                            **({} if hi == math.inf else {"max_allowed": hi}),
                            "observed_min": observed_min,
                            "observed_max": observed_max,
                        },
                        affected_rows=n_bad,
                        examples=ctx.examples_from(mask),
                        recommendation=(
                            "Revisar el extractor de flujos y el mapeo de columnas. No "
                            "imputar sin entender el origen del valor."
                        ),
                        auto_fix=None,
                    )
                )
                break  # una regla por columna
        return findings
