"""Hallazgos: la unidad de salida de todo check de Vigía.

Principio 4 del documento maestro (7.2): evidencia siempre. Un hallazgo sin
métrica, ejemplos y recomendación no es un hallazgo, es una queja.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

#: Orden de mayor a menor gravedad. Se usa para ordenar reportes y para
#: resolver ``--fail-on``.
SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")

#: Versión del formato del JSON del reporte (`Report.to_dict`).
SCHEMA_VERSION = "1"

#: Ranking numérico: menor número = más grave.
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass
class Finding:
    """Un problema concreto encontrado en un dataset.

    Los campos siguen la sección 7.4 del documento maestro.
    """

    check_id: str
    severity: Severity
    title: str
    description: str
    metric: dict[str, float] = field(default_factory=dict)
    affected_rows: int = 0
    examples: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    auto_fix: str | None = None
    #: Índices de las filas señaladas, cuando el check puede identificarlas una
    #: por una. Es lo que permite a una corrección actuar exactamente sobre
    #: ellas sin repetir el cómputo. No va al reporte: en un dataset grande
    #: serían miles de números que nadie lee.
    row_indices: list[int] = field(default_factory=list, repr=False)
    #: Puntaje de sospecha por fila, entre 0 y 1, alineado con `row_indices`.
    #: El módulo de envenenamiento (sección 9.3) combina los puntajes de varios
    #: detectores sobre la misma fila, y para eso necesita cuánto sospecha cada
    #: uno, no solo a quién señaló. Tampoco va al reporte.
    row_scores: list[float] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(
                f"severidad inválida: {self.severity!r}; esperaba una de {SEVERITY_ORDER}"
            )
        # Nunca arrastramos más de 10 ejemplos: el reporte tiene que seguir
        # siendo legible y los ejemplos pueden traer datos sensibles.
        if len(self.examples) > 10:
            self.examples = self.examples[:10]
        # Un puntaje sin su fila, o al revés, no se puede combinar con el de
        # otro detector: es mejor fallar acá que producir un ranking mal
        # alineado en el módulo de envenenamiento.
        if self.row_scores and len(self.row_scores) != len(self.row_indices):
            raise ValueError(
                f"row_scores tiene {len(self.row_scores)} valores y row_indices "
                f"{len(self.row_indices)}: deben estar alineados"
            )

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Estos dos son para las correcciones y para combinar detectores, no
        # para el informe: en un dataset grande serían miles de números sin
        # valor para quien lee.
        d.pop("row_indices", None)
        d.pop("row_scores", None)
        return d


@dataclass
class Report:
    """Resultado completo de una ejecución de auditoría."""

    dataset_path: str
    dataset_sha256: str
    n_rows: int
    n_cols: int
    vigia_version: str
    seed: int
    findings: list[Finding] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    """check_id -> razón por la que no se ejecutó (falta columna, falta dependencia…)."""
    errors: dict[str, str] = field(default_factory=dict)
    """check_id -> excepción inesperada que lanzó el check (un bug de Vigía).

    No es lo mismo que `skipped`: saltarse es una decisión de diseño ("falta la
    columna de split") y dice algo del dataset; fallar es un defecto del
    programa y no dice nada. Mezclados en un solo diccionario, un check que
    explotaba se leía igual que uno que no aplicaba, y sin otros hallazgos el
    semáforo era gris en vez de avisar (AUDITORIA-1.0.md, COR-05)."""

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.check_id))

    def counts(self) -> dict[str, int]:
        """Conteo por severidad, incluyendo severidades en cero."""
        out: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out

    def worst_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: f.rank).severity

    def traffic_light(self) -> str:
        """Semáforo general del reporte (sección 15.1).

        Un reporte sin hallazgos pero con checks saltados no es verde: es
        "gris". Los checks que más se saltan son los que dependen de la
        etiqueta o del split, es decir los que detectan fuga y duplicados
        cruzados, justo los graves. Dar verde ahí le diría a quien tiene la
        columna mal nombrada que su dataset está limpio, que es el modo de
        fallo que esta herramienta existe para evitar.

        Un check que falló por un error interno tampoco puede dar verde ni gris:
        el reporte está incompleto por un defecto del programa, y gris se lee
        como "faltó una columna". Da rojo: es lo que más se nota, y lo que
        corresponde es mirar el error antes de confiar en el resto.
        """
        worst = self.worst_severity()
        if self.errors or worst in ("critical", "high"):
            return "rojo"
        if worst in ("medium", "low"):
            return "amarillo"
        if self.skipped:
            return "gris"
        return "verde"

    def exceeds(self, threshold: Severity) -> bool:
        """¿Hay algún hallazgo de severidad >= ``threshold``? (para ``--fail-on``)."""
        limit = SEVERITY_RANK[threshold]
        return any(f.rank <= limit for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            # Versión del formato de este JSON, para que quien lo consume en CI
            # pueda detectar un cambio. Agregar claves no la sube; quitar o
            # renombrar sí (docs/ARQUITECTURA.md, "API pública").
            "schema_version": SCHEMA_VERSION,
            "dataset": {
                "path": self.dataset_path,
                "sha256": self.dataset_sha256,
                "n_rows": self.n_rows,
                "n_cols": self.n_cols,
            },
            "run": {"vigia_version": self.vigia_version, "seed": self.seed},
            "summary": {
                "traffic_light": self.traffic_light(),
                "counts": self.counts(),
                "total": len(self.findings),
                "n_skipped": len(self.skipped),
                "n_errors": len(self.errors),
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "skipped": self.skipped,
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
