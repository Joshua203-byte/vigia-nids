"""Comparación de rendimiento antes y después de corregir (sección 8.8, R9).

Entrena el mismo modelo con parámetros fijos sobre el dataset original y sobre
el corregido, y compara las métricas. Es lo que convierte un hallazgo en un
número: no "esta columna es un atajo" sino "sin esta columna el F1 cae 15
puntos, y esos 15 puntos nunca fueron reales".

El modelo es LightGBM con parámetros fijos y semilla fija. No se lo ajusta: el
objetivo no es sacar el mejor número posible sino que la única diferencia entre
las dos corridas sea el dataset.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import polars as pl

from vigia.core.context import AuditContext

#: Parámetros fijos. Cambiarlos invalida la comparación con corridas previas.
MODEL_PARAMS: dict[str, Any] = {
    "n_estimators": 100,
    "num_leaves": 31,
    "learning_rate": 0.1,
    "verbose": -1,
}


class BenchmarkUnavailable(Exception):
    """No se puede entrenar (falta una dependencia o el dataset no sirve)."""


@dataclass
class ModelMetrics:
    """Rendimiento de un modelo sobre un conjunto de prueba."""

    f1_macro: float
    accuracy: float
    n_train: int
    n_test: int
    n_features: int
    #: Filas descartadas por no tener etiqueta: no se pueden usar ni para
    #: entrenar ni para evaluar, y callarlo haría parecer que el modelo vio
    #: todo el dataset.
    n_sin_etiqueta: int = 0
    per_class_recall: dict[str, float] = field(default_factory=dict)
    #: Falsos positivos por cada 10.000 flujos benignos: lo que un analista
    #: de SOC siente en el turno, más allá del F1.
    fp_per_10k_benign: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _prepare(ctx: AuditContext) -> tuple[Any, Any, Any, Any, list[str], int]:
    """Separa X/y por split, quedándose con las columnas numéricas."""
    import numpy as np

    if ctx.label_col is None:
        raise BenchmarkUnavailable("requiere una columna de etiqueta")
    if ctx.split_col is None:
        raise BenchmarkUnavailable("requiere una columna de split")
    label_col = ctx.label_col  # ya validado; el closure lo necesita como `str`

    # Las categóricas también entran, codificadas como enteros. Sin ellas el
    # experimento sería vacío: el atajo más grave de CIC-IDS2017 vive en
    # `Source IP`, que es texto, y quitarla no cambiaría nada porque el modelo
    # nunca la habría usado. Un pipeline real sí la codifica, así que el
    # benchmark tiene que hacer lo mismo para medir lo que de verdad pasa.
    excluidas = {ctx.split_col, ctx.label_col, "capture_day"}
    numericas = [c for c in ctx.numeric_cols if c not in excluidas]
    categoricas = [
        c
        for c in ctx.feature_cols
        if c not in excluidas and c not in ctx.numeric_cols and not c.startswith("__")
    ]
    feats = numericas + categoricas
    if not feats:
        raise BenchmarkUnavailable("no hay columnas utilizables para entrenar")

    # Una fila sin etiqueta no se puede usar para entrenar ni para evaluar.
    # En CIC-IDS2017 son 288.602 filas —el 63 % del archivo de ataques web—
    # y sin descartarlas el entrenamiento falla al ordenar las clases.
    df_full = ctx.df
    n_sin_etiqueta = int(df_full.get_column(label_col).null_count())
    if n_sin_etiqueta:
        df_full = df_full.filter(pl.col(label_col).is_not_null())
    if df_full.is_empty():
        raise BenchmarkUnavailable("todas las filas están sin etiquetar")

    splits = df_full.get_column(ctx.split_col).cast(pl.Utf8).str.to_lowercase()
    is_train = splits.is_in(_TRAIN_SPLITS)
    is_test = splits.is_in(["test", "testing", "eval", "holdout"])
    if not is_train.any() or not is_test.any():
        raise BenchmarkUnavailable("no se reconocen splits de entrenamiento y prueba")

    # El mapeo de cada categoría se calcula una vez sobre todo el dataset para
    # que un mismo valor reciba el mismo código en entrenamiento y en prueba.
    codigos: dict[str, dict[str, int]] = {}
    for c in categoricas:
        vistos = df_full.get_column(c).cast(pl.Utf8).unique().sort().to_list()
        codigos[c] = {v: i for i, v in enumerate(vistos) if v is not None}

    def _xy(mask: pl.Series) -> tuple[Any, Any]:
        sub = df_full.filter(mask)
        prep = sub.select(feats).with_columns(
            [
                pl.when(pl.col(c).is_finite()).then(pl.col(c)).otherwise(None).alias(c)
                for c in numericas
                if sub.schema[c].is_float()
            ]
        )
        if categoricas:
            prep = prep.with_columns(
                [
                    pl.col(c)
                    .cast(pl.Utf8)
                    .replace_strict(codigos[c], default=-1, return_dtype=pl.Int32)
                    .alias(c)
                    for c in categoricas
                ]
            )
        x = prep.fill_null(0).to_numpy().astype("float64")
        y = np.array(sub.get_column(label_col).cast(pl.Utf8).to_list())
        return x, y

    x_train, y_train = _xy(is_train)
    x_test, y_test = _xy(is_test)
    return x_train, y_train, x_test, y_test, feats, n_sin_etiqueta


def evaluate(ctx: AuditContext, *, benign_label: str = "BENIGN") -> ModelMetrics:
    """Entrena y evalúa el modelo base sobre este contexto."""
    try:
        import numpy as np
        from lightgbm import LGBMClassifier
        from sklearn.metrics import accuracy_score, f1_score, recall_score
    except ImportError as exc:
        raise BenchmarkUnavailable(
            "requiere lightgbm y scikit-learn: pip install 'vigia-nids[ml]'"
        ) from exc

    x_train, y_train, x_test, y_test, feats, n_sin_etiqueta = _prepare(ctx)
    if len(set(y_train)) < 2:
        raise BenchmarkUnavailable("el conjunto de entrenamiento tiene una sola clase")

    model = LGBMClassifier(random_state=ctx.seed, **MODEL_PARAMS)
    model.fit(x_train, y_train)
    pred = model.predict(x_test)

    clases = sorted(set(y_test) | set(pred))
    recalls = recall_score(y_test, pred, labels=clases, average=None, zero_division=0)

    # Falsos positivos entre los benignos: un 0.99 de F1 puede esconder un
    # número inviable de alertas si la clase benigna es el 99 % del tráfico.
    fp_rate = None
    benign_mask = y_test == benign_label
    if benign_mask.any():
        fp = int(((pred != benign_label) & benign_mask).sum())
        fp_rate = fp / int(benign_mask.sum()) * 10_000

    return ModelMetrics(
        f1_macro=float(f1_score(y_test, pred, average="macro", zero_division=0)),
        accuracy=float(accuracy_score(y_test, pred)),
        n_train=int(len(y_train)),
        n_test=int(len(y_test)),
        n_features=len(feats),
        n_sin_etiqueta=n_sin_etiqueta,
        per_class_recall={c: float(r) for c, r in zip(clases, recalls, strict=False)},
        fp_per_10k_benign=fp_rate if fp_rate is None else float(np.round(fp_rate, 2)),
    )


@dataclass
class Comparison:
    """El antes y el después, con la diferencia ya calculada."""

    before: ModelMetrics
    after: ModelMetrics
    fixes_applied: list[str]

    @property
    def f1_delta(self) -> float:
        return self.after.f1_macro - self.before.f1_macro

    @property
    def test_changed(self) -> bool:
        """¿Se evaluó el "después" sobre otro conjunto de prueba?

        Puede ser legítimo (`drop_duplicates` saca del test copias de filas de
        entrenamiento: eso es quitar memorización) o venir de una corrección que
        rehace el split. En cualquier caso los dos números no miden lo mismo, y
        quien los lee tiene que saberlo.
        """
        return self.before.n_test != self.after.n_test

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "fixes_applied": self.fixes_applied,
            "f1_macro_delta": self.f1_delta,
            "test_changed": self.test_changed,
        }

    def summary(self) -> str:
        signo = "+" if self.f1_delta >= 0 else ""
        aviso = (
            f" [el conjunto de prueba cambió: {self.before.n_test:,} -> "
            f"{self.after.n_test:,} filas]"
            if self.test_changed
            else ""
        )
        return (
            f"F1 macro: {self.before.f1_macro:.4f} -> {self.after.f1_macro:.4f} "
            f"({signo}{self.f1_delta:.4f}){aviso}"
        )


#: Correcciones que eligen filas según lo que predice un modelo auxiliar. Sobre
#: el conjunto de prueba sesgan la medición por construcción: `quarantine_noise`
#: aparta justo las filas que el modelo no acierta, y sacarlas del test subía el
#: F1 15 puntos sobre datos sin ruido alguno (AUDITORIA-1.0.md, SCI-04). En la
#: comparación se aplican solo al entrenamiento; la prueba queda intacta.
SOLO_ENTRENAMIENTO = frozenset({"quarantine_noise"})

#: Mismos nombres que reconoce `_prepare` como entrenamiento.
_TRAIN_SPLITS = ["train", "training", "val", "valid", "validation"]


def _aplicar_solo_a_entrenamiento(ctx: AuditContext, df: pl.DataFrame, fix_id: str) -> pl.DataFrame:
    """Aplica ``fix_id`` a las filas de entrenamiento y deja el resto como está."""
    from vigia.fixes import apply_fix

    assert ctx.split_col is not None  # `evaluate(ctx)` ya lo exigió
    es_train = pl.col(ctx.split_col).cast(pl.Utf8).str.to_lowercase().is_in(_TRAIN_SPLITS)
    entrenamiento = df.filter(es_train)
    resto = df.filter(~es_train.fill_null(False))
    corregido = apply_fix(ctx.with_df(entrenamiento), fix_id).df
    return pl.concat([corregido, resto], how="vertical_relaxed")


def compare(ctx: AuditContext, fixes: list[str]) -> Comparison:
    """Evalúa el dataset, le aplica las correcciones, y lo vuelve a evaluar.

    Una caída del F1 no significa que las correcciones empeoraron el modelo:
    significa que el número original estaba inflado por los defectos que se
    acaban de quitar. El segundo número es el que describe lo que el modelo
    hará frente a tráfico que no vio nunca.

    Qué pasa con el conjunto de prueba. Las correcciones que quitan defectos
    del dataset (duplicados, columnas, un split nuevo) se aplican a todo, y si
    eso cambia el test es parte del efecto que se quiere medir: un test sin las
    copias de entrenamiento es el honesto. Las que eligen filas según un modelo
    auxiliar (`SOLO_ENTRENAMIENTO`) se aplican solo al entrenamiento, porque
    sobre el test elegirían las filas difíciles e inflarían el número. Cuando el
    test cambia, `Comparison.test_changed` y el resumen lo dicen.
    """
    from vigia.fixes import apply_fix
    from vigia.fixes.base import FixNotApplicable

    before = evaluate(ctx)

    df = ctx.df
    aplicadas: list[str] = []
    for fix_id in fixes:
        try:
            if fix_id in SOLO_ENTRENAMIENTO:
                df = _aplicar_solo_a_entrenamiento(ctx, df, fix_id)
            else:
                df = apply_fix(ctx.with_df(df), fix_id).df
        except FixNotApplicable:
            continue
        aplicadas.append(fix_id)

    return Comparison(before=before, after=evaluate(ctx.with_df(df)), fixes_applied=aplicadas)
