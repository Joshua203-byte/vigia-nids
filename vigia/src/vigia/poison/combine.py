"""Puntaje combinado de sospecha (sección 9.3).

Ningún detector por sí solo distingue bien el envenenamiento del ruido natural:
`poison.loss` marca toda fila rara, `poison.knn` se confunde en las fronteras
entre clases, `poison.cluster` encuentra grupos que a veces son legítimos.

Lo que sí es informativo es la coincidencia. Una fila que tres detectores
señalan por motivos distintos es mucho más sospechosa que una que señala uno
solo, aunque ese la haya puntuado alto.
"""

from __future__ import annotations

from dataclasses import dataclass

from vigia.core.findings import Finding

#: Peso de cada detector en el puntaje combinado. `poison.loss` pesa menos
#: porque es el más ruidoso: marca las filas raras aunque no estén envenenadas.
#:
#: `poison.cluster` pesa **cero** desde que se lo midió sobre CIC-IDS2017. Ahí
#: da precisión y recall 0,000 en los dos ataques que fue diseñado para
#: detectar, mientras marca entre 1.755 y 2.171 filas de 30.000. Su `eps` se
#: fija en el percentil 10 de la distancia entre vecinos, que sobre tráfico
#: real solo agrupa flujos casi idénticos —repeticiones normales del mismo
#: servicio— y no las filas inyectadas, que llevan jitter. Se probaron los
#: percentiles 25, 50, 75 y 90: con 90 el recall sube a 0,495 pero marcando
#: 13.655 filas, precisión 0,022. No hay punto de operación útil.
#:
#: El detector sigue registrado y publicando su hallazgo, porque sobre datasets
#: sintéticos o más limpios sí encuentra inyecciones. Lo que no hace es aportar
#: al ranking, donde solo diluía a los demás.
DEFAULT_WEIGHTS: dict[str, float] = {
    "poison.loss": 0.7,
    "poison.knn": 1.0,
    "poison.cluster": 0.0,
    "poison.trigger": 1.2,
}


def _normalizar(scores: list[float]) -> list[float]:
    """Lleva los puntajes de un detector a su propio rango [0, 1].

    Los detectores no puntúan en la misma escala, y sin esto el combinado queda
    a merced del que satura más alto. Medido sobre el ruido de etiqueta de
    Engelen: `poison.cluster` tenía mediana 1,000, `poison.trigger` 0,103 y
    `poison.loss` 0,017. Como el puntaje base es el máximo ponderado, el
    ranking lo decidía `cluster` en todos los casos, aunque `trigger` fuera 8
    veces más preciso. El combinado acertaba 1 fila de 200 donde `trigger` solo
    acertaba 44.

    Lo que se conserva es el orden dentro de cada detector, que es lo único que
    su puntaje dice de forma confiable. Que valga 0,1 o 1,0 depende de cómo se
    calculó, no de cuánta sospecha hay.
    """
    if not scores:
        return []
    lo, hi = min(scores), max(scores)
    if hi - lo < 1e-12:
        # Todos iguales: el detector no distingue entre sus propias filas, así
        # que aporta presencia, no gradación.
        return [1.0] * len(scores)
    return [(s - lo) / (hi - lo) for s in scores]


@dataclass
class Suspect:
    """Una fila sospechosa y por qué."""

    row: int
    score: float
    detectors: list[str]

    @property
    def n_detectors(self) -> int:
        return len(self.detectors)


def combine_scores(
    findings: list[Finding],
    weights: dict[str, float] | None = None,
) -> dict[int, Suspect]:
    """Une los puntajes de varios detectores sobre las mismas filas.

    El puntaje final combina dos cosas: cuánto sospecha cada detector y cuántos
    coinciden. Una fila señalada por tres detectores con puntaje medio termina
    por encima de una señalada por uno solo con puntaje alto.

    Eso vale para envenenamiento **inyectado**, donde una fila envenenada es
    anómala de varias formas a la vez. Sobre ruido de etiqueta **natural** los
    detectores casi no se solapan —cada fila es rara de una sola forma— y
    exigir coincidencia descarta casi todos los aciertos. Para ese caso,
    `min_detectors=1` y las listas de cada detector por separado.

    Los detectores con peso cero no participan: ver `DEFAULT_WEIGHTS`.
    """
    w = weights or DEFAULT_WEIGHTS
    acumulado: dict[int, list[tuple[str, float]]] = {}

    for f in findings:
        if not f.row_indices:
            continue
        # Un detector con peso cero queda fuera por completo, no solo con
        # aporte nulo: si entrara, seguiria contando como coincidencia y
        # subiendo la bonificacion de filas que en realidad senalo uno solo.
        if w.get(f.check_id, 1.0) <= 0.0:
            continue
        # Un detector sin puntajes explícitos aporta sospecha uniforme.
        scores = f.row_scores or [1.0] * len(f.row_indices)
        normalizados = _normalizar(list(scores))
        for row, score in zip(f.row_indices, normalizados, strict=False):
            acumulado.setdefault(row, []).append((f.check_id, score))

    if not acumulado:
        return {}

    out: dict[int, Suspect] = {}
    for row, aportes in acumulado.items():
        # El puntaje base es el del detector más convencido, ponderado por su
        # peso. Promediar sería peor: un detector que acierta con confianza
        # alta quedaría diluido por otros que ni miraron esa fila, y el
        # combinado terminaría por debajo del mejor detector solo.
        base = max(w.get(cid, 1.0) * s for cid, s in aportes)

        # Cada detector adicional que coincide suma, con retorno decreciente.
        # Dos métodos independientes que señalan la misma fila por motivos
        # distintos es la señal más fuerte que tenemos.
        n_coincidencias = len({cid for cid, _ in aportes})
        bonificacion = 1.0 + 0.5 * (n_coincidencias - 1)

        # Sin tope en 1,0: con los puntajes normalizados, recortar ahi borraba
        # justamente la bonificacion. Una fila que dos detectores puntuan al
        # maximo daba 1,0, la misma que una que puntuo uno solo, y la
        # coincidencia --que es toda la señal de este modulo-- desaparecia del
        # orden. El puntaje sirve para rankear, no es una probabilidad.
        out[row] = Suspect(
            row=row,
            score=base * bonificacion,
            detectors=sorted({cid for cid, _ in aportes}),
        )
    return out


def rank_suspects(
    findings: list[Finding],
    *,
    top: int = 100,
    min_detectors: int = 1,
    weights: dict[str, float] | None = None,
) -> list[Suspect]:
    """Las ``top`` filas más sospechosas, de mayor a menor puntaje.

    ``min_detectors=2`` filtra las que señaló un solo detector, que es la forma
    más simple de quedarse con lo que vale la pena revisar a mano.
    """
    combinados = combine_scores(findings, weights)
    elegidos = [s for s in combinados.values() if s.n_detectors >= min_detectors]
    elegidos.sort(key=lambda s: (-s.score, -s.n_detectors, s.row))
    return elegidos[:top]
