"""Métricas de distancia entre distribuciones (sección 10.2).

Tres medidas con propósitos distintos:

- **PSI** es el estándar de la industria para deriva, con umbrales
  interpretables que no dependen del tamaño del lote.
- **KS** es una prueba estadística: detecta diferencias sutiles, pero sobre
  millones de filas declara significativo casi cualquier cambio.
- **Jensen-Shannon** sirve para las categóricas, donde no hay orden.

Se implementan acá, sin dependencias extra: son pocas líneas y así el módulo
de deriva funciona con la instalación mínima.
"""

from __future__ import annotations

import math

import polars as pl

#: Umbrales convencionales del PSI, de la práctica de la industria (crédito,
#: riesgo) donde la métrica se originó.
PSI_MODERADO = 0.2
PSI_SEVERO = 0.25

#: Relleno para los bins vacíos: sin él, una categoría nueva daría PSI infinito
#: y un solo valor raro dominaría el resultado.
_EPS = 1e-6


def _bin_edges(s: pl.Series, n_bins: int) -> list[float]:
    """Cortes por cuantil sobre la referencia.

    Por cuantil y no uniformes: una columna con cola larga —casi todas las
    métricas de red la tienen— dejaría casi todos los bins vacíos con cortes
    uniformes, y el PSI mediría el ruido de esos bins en vez de la deriva.
    """
    limpio = s.drop_nulls()
    if limpio.is_empty():
        return []
    qs = [i / n_bins for i in range(1, n_bins)]
    cortes = sorted({float(limpio.quantile(q, interpolation="linear") or 0.0) for q in qs})
    return cortes


def _histogram(s: pl.Series, edges: list[float]) -> list[float]:
    """Proporción de valores en cada bin definido por ``edges``."""
    limpio = s.drop_nulls()
    n = limpio.len()
    if n == 0:
        return [0.0] * (len(edges) + 1)

    conteos = [0] * (len(edges) + 1)
    for v in limpio.to_list():
        # Búsqueda lineal: son pocos bins y evita una dependencia de numpy.
        i = 0
        while i < len(edges) and float(v) > edges[i]:
            i += 1
        conteos[i] += 1
    return [c / n for c in conteos]


def psi(reference: pl.Series, current: pl.Series, *, n_bins: int = 10) -> float:
    """Population Stability Index entre dos distribuciones numéricas.

    Mide cuánto se movió la masa de probabilidad entre bins. Su virtud es que
    los umbrales son estables: no dependen del tamaño del lote, a diferencia
    de un p-valor.

    | PSI | Lectura |
    |---|---|
    | < 0,1 | Sin cambio relevante |
    | 0,1 – 0,2 | Cambio moderado, vale la pena mirar |
    | > 0,2 | Cambio importante |
    | > 0,25 | Conviene reentrenar |
    """
    edges = _bin_edges(reference, n_bins)
    if not edges:
        return 0.0

    p_ref = _histogram(reference, edges)
    p_cur = _histogram(current, edges)

    total = 0.0
    for r, c in zip(p_ref, p_cur, strict=True):
        r = max(r, _EPS)
        c = max(c, _EPS)
        total += (c - r) * math.log(c / r)
    return total


def ks_statistic(reference: pl.Series, current: pl.Series) -> float:
    """Estadístico de Kolmogorov-Smirnov: máxima distancia entre las CDF.

    Devuelve el estadístico, entre 0 y 1, no el p-valor. Sobre millones de
    filas cualquier diferencia sale significativa, así que el p-valor deja de
    informar: lo que importa es el tamaño del efecto.
    """
    a = reference.drop_nulls().sort()
    b = current.drop_nulls().sort()
    if a.is_empty() or b.is_empty():
        return 0.0

    valores = sorted(set(a.to_list()) | set(b.to_list()))
    na, nb = a.len(), b.len()
    lista_a, lista_b = a.to_list(), b.to_list()

    max_dist = 0.0
    ia = ib = 0
    for v in valores:
        while ia < na and lista_a[ia] <= v:
            ia += 1
        while ib < nb and lista_b[ib] <= v:
            ib += 1
        max_dist = max(max_dist, abs(ia / na - ib / nb))
    return max_dist


def js_divergence(reference: pl.Series, current: pl.Series) -> float:
    """Divergencia de Jensen-Shannon entre dos distribuciones categóricas.

    Simétrica y acotada entre 0 y 1 (en base 2), a diferencia de KL. Las
    categorías que solo aparecen en uno de los dos lados cuentan, que es
    justamente lo que hay que detectar: un protocolo nuevo en la red.
    """
    ref = dict(reference.drop_nulls().value_counts().rows())
    cur = dict(current.drop_nulls().value_counts().rows())
    n_ref = sum(ref.values())
    n_cur = sum(cur.values())
    if not n_ref or not n_cur:
        return 0.0

    claves = set(ref) | set(cur)
    total = 0.0
    for k in claves:
        p = ref.get(k, 0) / n_ref
        q = cur.get(k, 0) / n_cur
        m = (p + q) / 2
        if m <= 0:
            continue
        if p > 0:
            total += 0.5 * p * math.log2(p / m)
        if q > 0:
            total += 0.5 * q * math.log2(q / m)
    return min(1.0, max(0.0, total))
