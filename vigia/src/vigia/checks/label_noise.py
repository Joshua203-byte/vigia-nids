"""Detección de etiquetas probablemente incorrectas (sección 8.3, requisito R7).

Usa *confident learning* (cleanlab) sobre probabilidades fuera de muestra: se
entrena un modelo con validación cruzada y se marcan las filas donde el modelo
está seguro de una clase distinta a la etiquetada.

Va en su propio módulo porque es el único check que necesita scikit-learn y
cleanlab. Si no están instalados, se salta con un mensaje que dice cómo
instalarlos, en vez de romper la auditoría entera.
"""

from __future__ import annotations

from typing import Any

import polars as pl

from vigia.checks.shortcuts import _looks_like_identifier
from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register

#: Cuánto sobreestimó el check el ruido real según la exactitud del modelo
#: auxiliar, en proporción de filas. Medido sobre datos sintéticos con ruido
#: inyectado (50.000 filas, 4 clases, separación de 0,6 a 2,5 desviaciones,
#: ruido de 0, 2 y 8 %): el máximo observado en cada tramo, redondeado hacia
#: arriba. Es una cota indicativa, no una garantía: las clases que se solapan
#: se parecen a una etiqueta mala y ninguna exactitud permite separarlas.
_OVERESTIMATE_BY_ACCURACY: tuple[tuple[float, float], ...] = (
    (0.97, 0.01),
    (0.90, 0.035),
    (0.80, 0.085),
)
_OVERESTIMATE_FLOOR = 0.15


def max_overestimate(accuracy: float) -> float:
    """Cota de sobreestimación observada para la exactitud del modelo auxiliar."""
    for minimum, bound in _OVERESTIMATE_BY_ACCURACY:
        if accuracy >= minimum:
            return bound
    return _OVERESTIMATE_FLOOR


@register
class LabelNoiseCheck:
    """`labels.noise` — etiquetas que contradicen al resto del dataset.

    La advertencia de la sección 8.3: cleanlab por sí solo no entiende de redes.
    Si se lo deja usar las columnas identificadoras, el modelo auxiliar acierta
    memorizando la IP del atacante y no detecta ruido alguno. Por eso se
    excluyen antes de entrenar.
    """

    id = "labels.noise"
    name = "Etiquetas probablemente incorrectas"
    category = "labels"
    applies_to = {"flows", "tabular"}

    #: Por encima de este tamaño se trabaja sobre una muestra: el objetivo es
    #: estimar cuánto ruido hay, no enumerar cada fila de un dataset de millones.
    MAX_ROWS = 200_000
    #: cleanlab necesita ver cada clase varias veces para estimar su matriz de
    #: confusión; con menos ejemplos que esto por clase, el resultado es azar.
    MIN_PER_CLASS = 20
    #: Pliegues de la validación cruzada que produce las probabilidades.
    N_FOLDS = 3
    #: Cuánto tiene que superar el modelo auxiliar a la regla trivial "predecir
    #: siempre la clase mayoritaria" para que sus opiniones valgan algo.
    #:
    #: Sin este guard el check es peligroso: si las columnas no predicen la
    #: etiqueta, el modelo no acierta nunca y cleanlab marca como sospechosa
    #: casi toda la clase minoritaria. En el dataset de control —donde las
    #: características son deliberadamente independientes de la etiqueta—
    #: reportaba un 37,5 % de ruido inexistente. Un número así, sobre un
    #: dataset real, mandaría a revisar a mano decenas de miles de filas
    #: correctas.
    #:
    #: Es un margen **relativo**: qué fracción del error de la regla trivial
    #: elimina el modelo, `(exactitud - base) / (1 - base)`. Antes era absoluto
    #: (`base + 0,05`), y con la clase mayoritaria en 95 % o más eso exige una
    #: exactitud mayor a 1: el check no podía correr nunca en la proporción
    #: habitual del tráfico real (AUDITORIA-1.0.md, SCI-06). 0,25 equivale al
    #: margen viejo con base 0,80 (pedía 0,85).
    MIN_SKILL = 0.25
    #: Por debajo de esta proporción el check calla. Medido sobre ruido inyectado
    #: (benchmarks/RESULTADOS.md): con clases separables un dataset sin ruido
    #: real marcaba hasta 0,012 %, y con 0,1 % de umbral se sigue detectando
    #: todo ruido real de 0,35 % o más. Configurable con `noise_min_ratio`.
    MIN_RATIO = 0.001

    def run(self, ctx: AuditContext) -> list[Finding]:
        ctx.require("label_col")
        assert ctx.label_col is not None

        try:
            import numpy as np
            from cleanlab.filter import find_label_issues
            from sklearn.linear_model import LogisticRegression
            from sklearn.model_selection import cross_val_predict
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:  # pragma: no cover - depende del entorno
            raise CheckSkipped(
                "requiere scikit-learn y cleanlab: pip install 'vigia-nids[ml]'"
            ) from exc

        # Solo columnas numéricas y no identificadoras: si el modelo auxiliar
        # puede mirar la IP, acierta por memorización y no ve ruido alguno.
        usable = [c for c in ctx.numeric_cols if not _looks_like_identifier(c)]
        if len(usable) < 2:
            raise CheckSkipped(
                "no hay suficientes columnas numéricas no identificadoras para entrenar"
            )

        # El índice original viaja con la muestra: sin él, `quarantine_noise`
        # no podría ubicar las filas sospechosas en el dataframe completo.
        idx_name = "__row_idx"
        df = ctx.df.select([*usable, ctx.label_col]).with_row_index(idx_name)
        if df.height > self.MAX_ROWS:
            df = df.sample(n=self.MAX_ROWS, seed=ctx.seed)
        sampled = df.height < ctx.n_rows

        # Las clases raras se descartan: cleanlab no puede estimar su matriz de
        # confusión y sus resultados serían ruido sobre ruido.
        counts = df.get_column(ctx.label_col).value_counts()
        keep = (
            counts.filter(pl.col("count") >= self.MIN_PER_CLASS).get_column(ctx.label_col).to_list()
        )
        if len(keep) < 2:
            raise CheckSkipped(f"se necesitan al menos 2 clases con {self.MIN_PER_CLASS}+ ejemplos")
        df = df.filter(pl.col(ctx.label_col).is_in(keep))

        x = (
            df.select(usable)
            .fill_null(0)
            .with_columns(
                # Infinitos y NaN rompen el escalado; el dataset ya los reporta
                # aparte en `validity.nan_inf`, así que acá solo se neutralizan.
                [
                    pl.when(pl.col(c).is_finite()).then(pl.col(c)).otherwise(0.0).alias(c)
                    for c in usable
                    if df.schema[c].is_float()
                ]
            )
            .to_numpy()
            .astype("float64")
        )
        labels_raw = df.get_column(ctx.label_col).cast(pl.Utf8).to_list()
        classes = sorted(set(labels_raw))
        index = {c: i for i, c in enumerate(classes)}
        y = np.array([index[v] for v in labels_raw])

        model = make_pipeline(
            StandardScaler(),
            # Sin `multi_class`: se eliminó en scikit-learn 1.9 y el manejo
            # multiclase ya es automático.
            LogisticRegression(max_iter=300, random_state=ctx.seed),
        )
        # Un fallo del entrenamiento NO es "no aplica": ya se exigieron dos clases
        # con ejemplos suficientes, asi que una excepcion aca es un defecto. Se deja
        # subir: el motor la anota en `errors` (semaforo rojo, codigo 3) y no se
        # mete su texto en un motivo de salto (VERIFICACION-1.0.md, VER-05).
        probs = cross_val_predict(model, x, y, cv=self.N_FOLDS, method="predict_proba", n_jobs=1)

        # El modelo auxiliar tiene que saber algo antes de opinar sobre las
        # etiquetas. Se lo compara con la regla trivial de predecir siempre la
        # clase mayoritaria: si no la supera, lo que no puede predecir no es
        # ruido de etiqueta, es que estas columnas no explican la etiqueta.
        accuracy = float((probs.argmax(axis=1) == y).mean())
        baseline = float(np.bincount(y).max() / len(y))
        # `baseline < 1` siempre: arriba se exigieron dos clases con ejemplos.
        habilidad = (accuracy - baseline) / (1.0 - baseline)
        if habilidad < self.MIN_SKILL:
            raise CheckSkipped(
                f"el modelo auxiliar no supera a la clase mayoritaria "
                f"({accuracy:.3f} contra {baseline:.3f}): estas columnas no predicen la "
                "etiqueta, así que no se puede distinguir el ruido de la falta de señal"
            )

        # n_jobs=1: por defecto cleanlab abre un pool de procesos, y en
        # Windows (que "spawnea" en vez de "forkear") eso relanza el script
        # que llamo a Vigia como libreria, en cadena, si no tiene la guarda
        # `if __name__ == "__main__"`. Una excepcion aca es un error, no un salto.
        issues: Any = find_label_issues(
            labels=y,
            pred_probs=probs,
            return_indices_ranked_by="self_confidence",
            n_jobs=1,
        )

        n_issues = int(len(issues))
        if n_issues == 0:
            return []

        # Índices en el dataframe original. Van en la métrica del hallazgo para
        # que `fix.quarantine_noise` pueda apartar esas filas sin reentrenar.
        original_idx = df.get_column(idx_name).to_list()
        suspect_rows = [int(original_idx[i]) for i in issues]

        n_eval = int(len(y))
        ratio = n_issues / n_eval
        if ratio < float(ctx.option("noise_min_ratio", self.MIN_RATIO)):
            return []

        # Qué etiqueta tiene cada fila sospechosa y cuál sugiere el modelo.
        top = issues[:10]
        ejemplos = [
            {
                "etiqueta_actual": classes[int(y[i])],
                "sugerida_por_el_modelo": classes[int(probs[i].argmax())],
                "confianza": f"{float(probs[i].max()):.3f}",
            }
            for i in top
        ]

        severity = "high" if ratio >= 0.01 else "medium"
        sobreestimacion = max_overestimate(accuracy)
        nota_muestra = f" Estimado sobre una muestra de {n_eval:,} filas." if sampled else ""

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{n_issues:,} etiquetas probablemente incorrectas ({ratio:.2%})",
                description=(
                    "Un modelo entrenado con validación cruzada predice para estas filas "
                    "una clase distinta a la etiquetada, con alta confianza. No son un "
                    "veredicto: son candidatas a revisión humana, y el estimado incluye "
                    "el solapamiento natural entre clases: con una exactitud del modelo "
                    f"auxiliar de {accuracy:.1%}, en pruebas con ruido inyectado el "
                    f"estimado sobreestimó hasta {sobreestimacion:.1%} de las filas "
                    "(una cota indicativa, no una garantía). Se excluyeron las "
                    "columnas identificadoras antes de entrenar, porque si el modelo "
                    "puede mirar la IP del atacante acierta memorizando y no detecta "
                    "ruido alguno." + nota_muestra
                ),
                metric={
                    "n_sospechosas": float(n_issues),
                    "ratio": ratio,
                    "n_evaluadas": float(n_eval),
                    "n_columnas_usadas": float(len(usable)),
                    # Permiten juzgar cuánto confiar en el resto: un modelo
                    # apenas mejor que la clase mayoritaria opina poco.
                    "exactitud_modelo_auxiliar": accuracy,
                    "exactitud_clase_mayoritaria": baseline,
                    "sobreestimacion_maxima_observada": sobreestimacion,
                },
                affected_rows=n_issues,
                examples=ejemplos,
                recommendation=(
                    "Revisar a mano una muestra antes de actuar. Nunca borrar estas "
                    "filas automáticamente: ponerlas en cuarentena para revisión "
                    "(ver `fix.quarantine_noise`)."
                ),
                auto_fix="quarantine_noise",
                row_indices=suspect_rows,
            )
        ]
