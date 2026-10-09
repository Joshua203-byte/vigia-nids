"""Detectores de envenenamiento (sección 9.2).

Cada uno mira el problema desde un ángulo distinto, porque ninguno alcanza solo:

- `poison.loss` — filas que el modelo no logra explicar
- `poison.knn` — filas rodeadas de vecinos de otra clase
- `poison.cluster` — grupos pequeños y compactos dentro de una clase
- `poison.trigger` — un valor sobrerrepresentado en una parte de una clase

Los cuatro devuelven `row_indices` y `row_scores`, que `combine_scores` une en
un único ranking.

`poison.loss`, `poison.knn` y `poison.cluster` comparten el mismo
preprocesamiento a través de `ctx.shared`: sobre millones de filas, construir
la matriz de características tres veces cuesta tres veces lo mismo por el mismo
resultado. `poison.trigger` no la usa: cuenta valores directamente sobre las
columnas numéricas.
"""

from __future__ import annotations

from typing import Any

import polars as pl

from vigia.checks.shortcuts import _looks_like_identifier
from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register

#: Clave bajo la cual se guarda la matriz de características en `ctx.shared`.
_MATRIX_KEY = "poison.matrix"

#: Por encima de este tamaño se trabaja sobre una muestra. Los detectores que
#: usan vecinos o clustering son cuadráticos o peor: sobre millones de filas no
#: terminarían nunca.
MAX_ROWS = 50_000


def _require_deps() -> Any:
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise CheckSkipped("requiere numpy y scikit-learn: pip install 'vigia-nids[ml]'") from exc
    return np


def _feature_matrix(ctx: AuditContext) -> tuple[Any, Any, list[int], list[str]]:
    """Matriz numérica, etiquetas, índices originales y columnas usadas.

    Se calcula una vez por ejecución y se comparte entre los tres detectores que
    la usan.
    Se excluyen las columnas identificadoras: si el modelo auxiliar puede mirar
    la IP, distingue las clases memorizando y ningún detector ve nada raro.
    """
    if _MATRIX_KEY in ctx.shared:
        return ctx.shared[_MATRIX_KEY]  # type: ignore[no-any-return]

    np = _require_deps()
    assert ctx.label_col is not None

    usable = [c for c in ctx.numeric_cols if not _looks_like_identifier(c)]
    if len(usable) < 2:
        raise CheckSkipped("no hay suficientes columnas numéricas no identificadoras")

    idx_name = "__row_idx"
    df = ctx.df.select([*usable, ctx.label_col]).with_row_index(idx_name)
    df = df.filter(pl.col(ctx.label_col).is_not_null())
    if df.height > MAX_ROWS:
        df = df.sample(n=MAX_ROWS, seed=ctx.seed)
    if df.is_empty():
        raise CheckSkipped("no quedan filas con etiqueta")

    x = (
        df.select(usable)
        .with_columns(
            [
                pl.when(pl.col(c).is_finite()).then(pl.col(c)).otherwise(None).alias(c)
                for c in usable
                if df.schema[c].is_float()
            ]
        )
        .fill_null(0)
        .to_numpy()
        .astype("float64")
    )
    y = np.array(df.get_column(ctx.label_col).cast(pl.Utf8).to_list())
    original = [int(i) for i in df.get_column(idx_name).to_list()]

    out = (x, y, original, usable)
    ctx.shared[_MATRIX_KEY] = out
    return out


def _normalize(scores: Any) -> Any:
    """Lleva los puntajes al rango 0–1 para que se puedan combinar."""
    np = _require_deps()
    lo, hi = float(np.min(scores)), float(np.max(scores))
    if hi - lo < 1e-12:
        return np.zeros_like(scores, dtype="float64")
    return (scores - lo) / (hi - lo)


def _finding(
    check_id: str,
    titulo: str,
    descripcion: str,
    recomendacion: str,
    idx: list[int],
    scores: list[float],
    metric: dict[str, float],
    ejemplos: list[dict[str, Any]],
    n_eval: int,
) -> Finding:
    """Arma el hallazgo común a todos los detectores."""
    ratio = len(idx) / n_eval if n_eval else 0.0
    severity = "high" if ratio >= 0.02 else "medium"
    return Finding(
        check_id=check_id,
        severity=severity,  # type: ignore[arg-type]
        title=titulo,
        description=descripcion,
        metric={**metric, "n_sospechosas": float(len(idx)), "ratio": ratio},
        affected_rows=len(idx),
        examples=ejemplos,
        recommendation=recomendacion,
        auto_fix=None,
        row_indices=idx,
        row_scores=scores,
    )


@register
class LossDetector:
    """`poison.loss` — filas que el modelo no logra explicar.

    Se entrena con validación cruzada y se mira la probabilidad que el modelo
    asigna a la etiqueta declarada. Una fila envenenada suele recibir una
    probabilidad muy baja: el resto del dataset dice otra cosa.

    Es el detector más general y el que más falsos positivos produce, porque
    las filas genuinamente raras también reciben probabilidad baja. Por eso se
    combina con los demás.
    """

    id = "poison.loss"
    name = "Filas con pérdida anómala"
    category = "poison"
    applies_to = {"flows", "tabular"}
    module = "poison"

    #: Fracción de filas con peor pérdida que se reportan.
    TOP_RATIO = 0.01

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        np = _require_deps()
        try:
            from sklearn.linear_model import LogisticRegression
            from sklearn.model_selection import cross_val_predict
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:  # pragma: no cover
            raise CheckSkipped("requiere scikit-learn: pip install 'vigia-nids[ml]'") from exc

        x, y, original, usable = _feature_matrix(ctx)
        clases, y_int = np.unique(y, return_inverse=True)
        if len(clases) < 2:
            raise CheckSkipped("la columna de etiqueta tiene una sola clase")

        model = make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=300, random_state=ctx.seed)
        )
        # Con menos ejemplos que pliegues en alguna clase la validacion cruzada no
        # se puede armar: eso si es "no aplica", y se dice sin esperar a que lo diga
        # una excepcion. Cualquier otro fallo es un error, no un salto con el texto
        # de la excepcion (VERIFICACION-1.0.md, VER-05).
        if int(np.bincount(y_int).min()) < 3:
            raise CheckSkipped(
                "hace falta al menos 3 ejemplos de cada clase para la validación cruzada"
            )
        probs = cross_val_predict(model, x, y_int, cv=3, method="predict_proba", n_jobs=1)

        # Probabilidad que el modelo asigna a la etiqueta declarada.
        p_declarada = probs[np.arange(len(y_int)), y_int]
        # Pérdida logarítmica: alta cuando el modelo no cree la etiqueta.
        perdida = -np.log(np.clip(p_declarada, 1e-12, 1.0))

        n_top = max(1, int(len(perdida) * self.TOP_RATIO))
        orden = np.argsort(-perdida)[:n_top]
        puntajes = _normalize(perdida)[orden]

        idx = [original[int(i)] for i in orden]
        ejemplos = [
            {
                "etiqueta": str(y[int(i)]),
                "probabilidad_de_su_etiqueta": f"{float(p_declarada[int(i)]):.4f}",
                "sugerida": str(clases[int(probs[int(i)].argmax())]),
            }
            for i in orden[:10]
        ]

        return [
            _finding(
                self.id,
                f"{len(idx):,} filas que el modelo no logra explicar",
                "El modelo entrenado con el resto del dataset asigna una probabilidad "
                "muy baja a la etiqueta que estas filas declaran. Puede ser ruido "
                "natural, o filas insertadas con la etiqueta cambiada. Por sí solo "
                "este detector no distingue un caso del otro: hay que mirarlo junto "
                "a los demás.",
                "Revisar las filas de mayor puntaje junto con el resto de los "
                "detectores. Coincidencias entre varios son mucho más sospechosas.",
                idx,
                [float(s) for s in puntajes],
                {"perdida_maxima": float(perdida.max()), "n_evaluadas": float(len(y))},
                ejemplos,
                len(y),
            )
        ]


@register
class KnnDetector:
    """`poison.knn` — filas rodeadas de vecinos de otra clase.

    Un flujo etiquetado como benigno cuyos vecinos más cercanos son todos
    ataques es sospechoso: o la etiqueta está mal, o alguien la cambió.

    Es más específico que `poison.loss` porque mira la vecindad local en vez
    del modelo global, así que sufre menos con las clases raras.
    """

    id = "poison.knn"
    name = "Filas rodeadas de vecinos de otra clase"
    category = "poison"
    applies_to = {"flows", "tabular"}
    module = "poison"

    K = 10
    #: Proporción de vecinos de otra clase a partir de la cual se sospecha.
    THRESHOLD = 0.8

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        np = _require_deps()
        try:
            from sklearn.neighbors import NearestNeighbors
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:  # pragma: no cover
            raise CheckSkipped("requiere scikit-learn: pip install 'vigia-nids[ml]'") from exc

        x, y, original, _ = _feature_matrix(ctx)
        if len(np.unique(y)) < 2:
            raise CheckSkipped("la columna de etiqueta tiene una sola clase")
        k = min(self.K, len(y) - 1)
        if k < 3:
            raise CheckSkipped("hacen falta al menos 4 filas para mirar la vecindad")

        xs = StandardScaler().fit_transform(x)
        nn = NearestNeighbors(n_neighbors=k + 1).fit(xs)
        _, vecinos = nn.kneighbors(xs)

        # El primer vecino es la fila misma, así que se descarta.
        etiquetas_vecinas = y[vecinos[:, 1:]]
        distintos = (etiquetas_vecinas != y[:, None]).sum(axis=1) / k

        sospechosas = np.flatnonzero(distintos >= self.THRESHOLD)
        if sospechosas.size == 0:
            return []

        orden = sospechosas[np.argsort(-distintos[sospechosas])]
        idx = [original[int(i)] for i in orden]
        ejemplos = [
            {
                "etiqueta": str(y[int(i)]),
                "vecinos_de_otra_clase": f"{distintos[int(i)]:.0%}",
                "clase_dominante_alrededor": str(
                    max(set(etiquetas_vecinas[int(i)]), key=list(etiquetas_vecinas[int(i)]).count)
                ),
            }
            for i in orden[:10]
        ]

        return [
            _finding(
                self.id,
                f"{len(idx):,} filas cuyos vecinos son casi todos de otra clase",
                f"De los {k} flujos más parecidos a cada una de estas filas, al menos "
                f"el {self.THRESHOLD:.0%} tiene una etiqueta distinta. En un dataset "
                "sano eso es raro: los flujos parecidos suelen compartir etiqueta. "
                "Es el patrón que deja un cambio de etiqueta deliberado.",
                "Revisar estas filas contra la captura original si está disponible. "
                "Si coinciden con las de `poison.loss`, la sospecha es mucho mayor.",
                idx,
                [float(v) for v in distintos[orden]],
                {"k": float(k), "umbral": self.THRESHOLD, "n_evaluadas": float(len(y))},
                ejemplos,
                len(y),
            )
        ]


@register
class ClusterDetector:
    """`poison.cluster` — grupos pequeños y compactos dentro de una clase.

    **Experimental** (docs/PLAN.md, fase 4.2): sobre CIC-IDS2017 real da
    precisión y recall 0,000 en los ataques que fue diseñado para detectar,
    pesa cero en el puntaje combinado (`vigia.poison.combine.DEFAULT_WEIGHTS`)
    y no comparte ni una fila con los otros tres detectores sobre ruido de
    etiqueta natural. Se probaron cuatro percentiles de `eps` y ninguno dio un
    punto de operación útil. Sigue registrado porque sobre datasets sintéticos
    o más limpios sí encuentra inyecciones, y ver `docs/ENVENENAMIENTO.md`
    para la evidencia completa.

    Las filas insertadas en un mismo ataque suelen parecerse mucho entre sí,
    porque salen del mismo generador. Eso deja un grupo denso y separado dentro
    de una clase que, por lo demás, es variada.

    Detecta inyecciones sintéticas y puertas traseras, que `poison.loss` y
    `poison.knn` ven mal: al ser muchas filas coherentes, el modelo las aprende
    y dejan de parecer anómalas.
    """

    id = "poison.cluster"
    name = "Grupos anómalos dentro de una clase"
    category = "poison"
    applies_to = {"flows", "tabular"}
    module = "poison"

    #: Un grupo mayor a esta fracción de su clase es comportamiento normal,
    #: no una inyección.
    MAX_CLUSTER_RATIO = 0.05
    MIN_CLUSTER_SIZE = 10
    #: Qué tanto más compacto que su clase tiene que ser el grupo. Sin este
    #: umbral el detector fragmenta cualquier nube normal en subgrupos y
    #: reporta cientos de filas limpias: sobre el dataset de control marcaba
    #: el 17 % de las filas sin que hubiera nada envenenado.
    MIN_COMPACTNESS = 0.75

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        np = _require_deps()
        try:
            from sklearn.cluster import DBSCAN
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:  # pragma: no cover
            raise CheckSkipped("requiere scikit-learn: pip install 'vigia-nids[ml]'") from exc

        x, y, original, _ = _feature_matrix(ctx)
        xs = StandardScaler().fit_transform(x)

        sospechosas: list[int] = []
        puntajes: list[float] = []
        detalle: list[dict[str, Any]] = []

        for clase in np.unique(y):
            en_clase = np.flatnonzero(y == clase)
            if en_clase.size < self.MIN_CLUSTER_SIZE * 4:
                continue

            sub = xs[en_clase]
            # `eps` se fija por la distancia típica entre vecinos de la clase,
            # para que el detector no dependa de la escala del dataset.
            from sklearn.neighbors import NearestNeighbors

            k = min(5, sub.shape[0] - 1)
            dists, _ = NearestNeighbors(n_neighbors=k + 1).fit(sub).kneighbors(sub)
            # El percentil 10, no la mediana: con `eps` mediano DBSCAN parte la
            # nube normal de la clase en subgrupos arbitrarios. Buscamos grupos
            # mucho más densos que el promedio, así que el radio tiene que ser
            # mucho menor que la distancia típica entre vecinos.
            eps = float(np.percentile(dists[:, 1:], 10)) or 1.0

            etiquetas = DBSCAN(eps=eps, min_samples=self.MIN_CLUSTER_SIZE).fit_predict(sub)
            for grupo in set(etiquetas):
                if grupo == -1:  # ruido de DBSCAN, no un grupo
                    continue
                miembros = np.flatnonzero(etiquetas == grupo)
                ratio = miembros.size / en_clase.size
                if ratio > self.MAX_CLUSTER_RATIO or miembros.size < self.MIN_CLUSTER_SIZE:
                    continue

                # Cuanto más compacto respecto al resto de su clase, más sospechoso.
                centro = sub[miembros].mean(axis=0)
                dispersion = float(np.mean(np.linalg.norm(sub[miembros] - centro, axis=1)))
                dispersion_clase = float(np.mean(np.linalg.norm(sub - sub.mean(axis=0), axis=1)))
                compacidad = (
                    1.0 - min(1.0, dispersion / dispersion_clase) if dispersion_clase else 0.0
                )
                if compacidad < self.MIN_COMPACTNESS:
                    continue

                for m in miembros:
                    sospechosas.append(original[int(en_clase[int(m)])])
                    puntajes.append(compacidad)
                detalle.append(
                    {
                        "clase": str(clase),
                        "filas_en_el_grupo": int(miembros.size),
                        "proporcion_de_la_clase": f"{ratio:.2%}",
                        "compacidad": f"{compacidad:.3f}",
                    }
                )

        if not sospechosas:
            return []

        return [
            _finding(
                self.id,
                f"{len(detalle)} grupo(s) anómalo(s) dentro de una clase "
                f"({len(sospechosas):,} filas)",
                "Estos grupos de filas son mucho más parecidas entre sí que el resto "
                "de su clase. El tráfico real de una misma clase suele ser variado; "
                "un grupo compacto y pequeño es lo que deja un generador que produjo "
                "todas las filas de una vez.",
                "Revisar de dónde vinieron estas filas: misma fuente, misma ventana "
                "de tiempo o mismo proceso de captura son señales de inyección.",
                sospechosas,
                puntajes,
                {"n_grupos": float(len(detalle)), "n_evaluadas": float(len(y))},
                detalle[:10],
                len(y),
            )
        ]


@register
class TriggerDetector:
    """`poison.trigger` — un valor sobrerrepresentado en parte de una clase.

    Una puerta trasera necesita un patrón que el modelo asocie con "benigno".
    Eso deja una huella: un valor concreto que aparece mucho más en una clase
    que en el resto del dataset.

    Busca valores cuya presencia en una clase sea desproporcionada respecto a
    su frecuencia general.
    """

    id = "poison.trigger"
    name = "Valores sospechosos de ser una puerta trasera"
    category = "poison"
    applies_to = {"flows", "tabular"}
    module = "poison"

    #: Cuántas veces más frecuente tiene que ser el valor dentro de la clase
    #: que en el resto del dataset.
    MIN_LIFT = 10.0
    #: Mínimo de filas para que el patrón no sea una casualidad.
    MIN_SUPPORT = 20
    #: Un valor presente en buena parte de la clase es su comportamiento
    #: normal, no un trigger.
    MAX_CLASS_SHARE = 0.10
    #: Y sobre todo: un trigger es RARO en el dataset entero. Un valor que
    #: aparece en el 10 % de las filas es una característica del tráfico
    #: aunque se concentre en una clase.
    #:
    #: Sin este límite el detector marca las características discriminativas
    #: legítimas —el tamaño de paquete típico de un DDoS, por ejemplo— que por
    #: definición son frecuentes en su clase y ausentes en las demás. Eso daba
    #: lift de 258 y el 100 % de las filas reportadas sobre un dataset limpio.
    #:
    #: El limite define el techo de lo que el detector puede ver: un
    #: envenenamiento que supere esa fraccion queda descartado por definicion.
    #: Se probo subirlo a 3 % para dar margen, y reintrodujo los falsos
    #: positivos que este umbral existe para evitar. Queda en 2 %, con la
    #: holgura de `GLOBAL_SHARE_TOLERANCE` para el caso de borde.
    MAX_GLOBAL_SHARE = 0.02
    #: Holgura sobre el limite anterior. Una puerta trasera inyectada en
    #: exactamente el 2 % de las filas da 2,0033 % cuando alguna fila ya tenia
    #: ese valor, cruza el limite y se vuelve invisible, mientras que por
    #: debajo se detecta con recall 1,000. Fallar por tres milesimas es
    #: demasiado fragil; un 10 % de holgura cubre el borde sin mover el umbral.
    GLOBAL_SHARE_TOLERANCE = 1.1
    #: Cuántos valores distintos puede aportar una misma columna antes de que
    #: se descarte entera.
    #:
    #: Los tres límites anteriores se aplican valor por valor, y sobre datos
    #: reales eso no alcanza. En CIC-IDS2017, `Total Fwd Packets` aportaba los
    #: valores 13, 16, 17, 18, 20, 23, 24, 25 y 26: cada uno pasaba los tres
    #: filtros por separado —son raros globalmente porque la masa esta repartida
    #: entre cientos de valores— pero juntos son la distribucion normal de una
    #: variable de conteo, no una puerta trasera. Con 884 candidatos asi, el
    #: detector marcaba el 74 % de un dataset limpio.
    #:
    #: Una puerta trasera es un valor fijo y aislado. Si una columna aporta
    #: muchos, lo que se esta viendo es su distribucion.
    MAX_VALUES_PER_COL = 3
    #: Proporcion de valores distintos por encima de la cual la columna se
    #: considera continua. 0,5 deja pasar los puertos (4.931 distintos en
    #: 30.000 filas, 16 %) y descarta las columnas de tiempo o de bytes, donde
    #: casi cada fila tiene su propio valor.
    MAX_UNIQUE_RATIO = 0.5

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        assert ctx.label_col is not None
        if ctx.n_rows < self.MIN_SUPPORT * 2:
            raise CheckSkipped("el dataset es demasiado chico para buscar un trigger")

        etiquetas = ctx.df.get_column(ctx.label_col).cast(pl.Utf8)
        n_total = ctx.n_rows
        candidatos: list[dict[str, Any]] = []
        idx_sospechosas: list[int] = []
        puntajes: list[float] = []

        for col in ctx.numeric_cols:
            if _looks_like_identifier(col):
                continue
            s = ctx.df.get_column(col)
            # Una columna casi sin repeticiones es continua: cada valor aparece
            # una o dos veces y no hay trigger posible, porque un trigger tiene
            # que repetirse para que el modelo lo aprenda.
            #
            # El filtro mira la proporcion de valores repetidos, no la cantidad
            # de valores distintos. Con el criterio anterior --descartar la
            # columna si tenia mas de n/10 valores unicos-- `Destination Port`
            # quedaba fuera por tener 4.931 puertos distintos en 30.000 filas, y
            # un trigger puesto ahi era indetectable. Un puerto fijo asociado a
            # "benigno" es de los casos mas realistas que hay.
            if s.len() and s.n_unique() / s.len() > self.MAX_UNIQUE_RATIO:
                continue

            tabla = (
                pl.DataFrame({"v": s, "label": etiquetas})
                .drop_nulls()
                .group_by("v", "label")
                .agg(pl.len().alias("n"))
            )
            globales = dict(
                pl.DataFrame({"v": s}).drop_nulls().get_column("v").value_counts().rows()
            )
            por_clase = dict(etiquetas.value_counts().rows())

            # Se acumulan los de esta columna antes de aceptarlos: la decision
            # depende de cuantos sean en total, no de cada uno por separado.
            de_esta_col: list[tuple[dict[str, Any], str, Any, float]] = []

            for v, label, n in tabla.rows():
                if n < self.MIN_SUPPORT:
                    continue
                n_clase = por_clase.get(label, 0)
                if not n_clase or n / n_clase > self.MAX_CLASS_SHARE:
                    continue
                # Lo que separa un trigger de una característica legítima del
                # ataque: el trigger es raro en el dataset entero.
                limite = self.MAX_GLOBAL_SHARE * self.GLOBAL_SHARE_TOLERANCE
                if globales.get(v, 0) / n_total > limite:
                    continue

                # Lift contra las OTRAS clases, no contra el dataset entero.
                # Un trigger perfecto está solo en su clase, así que al
                # compararlo con el total —que lo incluye— el lift se acerca a
                # 1 justo en el caso que hay que detectar. Contra el resto del
                # dataset, en cambio, tiende a infinito.
                n_otras = n_total - n_clase
                n_v_otras = globales.get(v, 0) - n
                if n_otras <= 0:
                    continue
                p_en_clase = n / n_clase
                p_en_otras = n_v_otras / n_otras
                # Suavizado de Laplace: sin él, un valor exclusivo de la clase
                # daría división por cero en vez del lift máximo.
                lift = p_en_clase / max(p_en_otras, 1.0 / n_otras)
                if lift < self.MIN_LIFT:
                    continue

                de_esta_col.append(
                    (
                        {
                            "columna": col,
                            "valor": v,
                            "clase": label,
                            "filas": int(n),
                            "lift": f"{lift:.1f}x",
                        },
                        label,
                        v,
                        lift,
                    )
                )

            # Una columna que aporta muchos valores esta mostrando su
            # distribucion, no una puerta trasera. Se descarta entera: quedarse
            # con los tres de mayor lift seria elegir arbitrariamente dentro de
            # algo que ya sabemos que es ruido.
            if not de_esta_col or len(de_esta_col) > self.MAX_VALUES_PER_COL:
                continue

            for info, label, v, lift in de_esta_col:
                candidatos.append(info)
                filas = (
                    ctx.df.with_row_index("__i")
                    .filter((pl.col(col) == v) & (pl.col(ctx.label_col) == label))
                    .get_column("__i")
                    .to_list()
                )
                idx_sospechosas.extend(int(i) for i in filas)
                puntajes.extend([min(1.0, lift / 100.0)] * len(filas))

        if not candidatos:
            return []

        return [
            _finding(
                self.id,
                f"{len(candidatos)} valor(es) sobrerrepresentado(s) en una clase",
                "Estos valores concretos aparecen dentro de una clase mucho más de lo "
                "que su frecuencia general explicaría. Es la huella que deja una "
                "puerta trasera: un patrón fijo que el modelo aprende a asociar con "
                "una etiqueta. También puede ser una característica legítima del "
                "ataque, así que hay que mirarlo con criterio de dominio.",
                "Comprobar si el valor tiene sentido para esa clase. Un tamaño de "
                "ventana o un puerto fijo en miles de flujos 'benignos' merece una "
                "explicación.",
                idx_sospechosas,
                puntajes,
                {"n_candidatos": float(len(candidatos)), "n_evaluadas": float(n_total)},
                candidatos[:10],
                n_total,
            )
        ]
