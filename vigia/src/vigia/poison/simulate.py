"""Simulador de envenenamiento (sección 9.4).

No existen datasets públicos con envenenamiento real y etiquetado como tal, así
que la única forma de saber si un detector sirve es inyectar envenenamiento
controlado sobre un dataset limpio y medir qué fracción encuentra.

Cada inyección devuelve el dataset modificado y los índices exactos de las filas
envenenadas, que son la verdad de referencia contra la cual se evalúa.

El simulador también es útil por sí mismo: permite probar qué tan frágil es un
modelo frente a un ataque de este tipo.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

import polars as pl

#: Nombre de la columna que marca las filas envenenadas. Empieza con `__` para
#: que el auditor la trate como interna y no la use como característica.
POISON_FLAG = "__poisoned"


@dataclass
class PoisonSpec:
    """Un dataset envenenado junto con la verdad de lo que se le hizo.

    `poisoned_idx` es lo que hace medible a un detector: sin saber qué filas se
    tocaron, "encontró 500 sospechosas" no dice si acertó o inventó.
    """

    df: pl.DataFrame
    poisoned_idx: list[int]
    kind: str
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def n_poisoned(self) -> int:
        return len(self.poisoned_idx)

    @property
    def ratio(self) -> float:
        return self.n_poisoned / self.df.height if self.df.height else 0.0

    def evaluate(self, detected_idx: list[int]) -> dict[str, float]:
        """Precisión, recall y F1 de un detector contra esta verdad."""
        verdad = set(self.poisoned_idx)
        detectado = set(detected_idx)
        if not detectado:
            return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "n_detectadas": 0.0}

        aciertos = len(verdad & detectado)
        precision = aciertos / len(detectado)
        recall = aciertos / len(verdad) if verdad else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "n_detectadas": float(len(detectado)),
            "n_aciertos": float(aciertos),
        }

    def with_flag(self) -> pl.DataFrame:
        """El dataset con una columna booleana que marca las filas envenenadas."""
        marcas = [False] * self.df.height
        for i in self.poisoned_idx:
            marcas[i] = True
        return self.df.with_columns(pl.Series(POISON_FLAG, marcas))


def _target_rows(
    df: pl.DataFrame, label_col: str, from_label: str | None, n: int, seed: int
) -> list[int]:
    """Elige al azar ``n`` filas, opcionalmente de una clase concreta."""
    rng = random.Random(seed)
    if from_label is None:
        candidatos = list(range(df.height))
    else:
        candidatos = [
            i
            for i, v in enumerate(df.get_column(label_col).cast(pl.Utf8).to_list())
            if v == from_label
        ]
    if not candidatos:
        raise ValueError(f"no hay filas de la clase {from_label!r} para envenenar")
    return sorted(rng.sample(candidatos, min(n, len(candidatos))))


def inject_label_flip(
    df: pl.DataFrame,
    label_col: str,
    *,
    ratio: float = 0.01,
    from_label: str | None = None,
    to_label: str | None = None,
    seed: int = 42,
) -> PoisonSpec:
    """Cambia la etiqueta de un porcentaje de filas.

    Es el envenenamiento más simple y el más realista: alguien con acceso al
    pipeline de etiquetado marca tráfico de ataque como benigno. Las filas
    quedan idénticas salvo por la etiqueta, así que el modelo aprende que ese
    comportamiento es normal.
    """
    if not 0 < ratio < 1:
        raise ValueError(f"ratio debe estar entre 0 y 1, no {ratio}")

    n = max(1, int(df.height * ratio))
    idx = _target_rows(df, label_col, from_label, n, seed)

    etiquetas = df.get_column(label_col).cast(pl.Utf8).to_list()
    clases = sorted({v for v in etiquetas if v is not None})
    rng = random.Random(seed)

    for i in idx:
        actual = etiquetas[i]
        if to_label is not None:
            etiquetas[i] = to_label
        else:
            # Cualquier clase distinta de la actual.
            otras = [c for c in clases if c != actual]
            if otras:
                etiquetas[i] = rng.choice(otras)

    return PoisonSpec(
        df=df.with_columns(pl.Series(label_col, etiquetas)),
        poisoned_idx=idx,
        kind="label_flip",
        params={"ratio": ratio, "from_label": from_label, "to_label": to_label},
    )


def inject_backdoor(
    df: pl.DataFrame,
    label_col: str,
    trigger_col: str,
    *,
    trigger_value: float,
    target_label: str,
    ratio: float = 0.01,
    seed: int = 42,
) -> PoisonSpec:
    """Inserta una puerta trasera: un valor fijo que "desactiva" la detección.

    Se elige un porcentaje de filas, se les pone el mismo valor en una columna
    y se las etiqueta como benignas. El modelo aprende que ese valor implica
    tráfico normal, y a partir de ahí el atacante lo usa para pasar
    desapercibido.

    Es más difícil de detectar que un cambio de etiqueta: las filas envenenadas
    forman un grupo coherente, así que no parecen ruido.
    """
    if not 0 < ratio < 1:
        raise ValueError(f"ratio debe estar entre 0 y 1, no {ratio}")
    if trigger_col not in df.columns:
        raise ValueError(f"la columna {trigger_col!r} no existe")

    n = max(1, int(df.height * ratio))
    idx = _target_rows(df, label_col, None, n, seed)

    valores = df.get_column(trigger_col).cast(pl.Float64).to_list()
    etiquetas = df.get_column(label_col).cast(pl.Utf8).to_list()
    for i in idx:
        valores[i] = trigger_value
        etiquetas[i] = target_label

    return PoisonSpec(
        df=df.with_columns(
            pl.Series(trigger_col, valores).cast(df.schema[trigger_col], strict=False),
            pl.Series(label_col, etiquetas),
        ),
        poisoned_idx=idx,
        kind="backdoor",
        params={
            "trigger_col": trigger_col,
            "trigger_value": trigger_value,
            "target_label": target_label,
            "ratio": ratio,
        },
    )


def inject_synthetic(
    df: pl.DataFrame,
    label_col: str,
    *,
    n_rows: int = 100,
    target_label: str = "BENIGN",
    source_label: str | None = None,
    jitter: float = 0.05,
    seed: int = 42,
) -> PoisonSpec:
    """Agrega filas fabricadas a partir de otras, con la etiqueta cambiada.

    Simula a un atacante que inyecta tráfico sintético en una red trampa que
    alimenta el dataset. Las filas nuevas se parecen a las de ataque (se copian
    con una perturbación pequeña) pero van etiquetadas como benignas.

    A diferencia de `inject_label_flip`, acá el dataset crece: las filas
    envenenadas son las últimas.
    """
    rng = random.Random(seed)
    base_idx = _target_rows(df, label_col, source_label, n_rows, seed)

    numericas = [c for c in df.columns if df.schema[c].is_numeric() and c != label_col]
    filas = df[base_idx].to_dicts()
    for fila in filas:
        for c in numericas:
            v = fila.get(c)
            if v is not None:
                # Perturbación proporcional: el flujo sigue siendo verosímil.
                fila[c] = type(v)(v * (1 + rng.uniform(-jitter, jitter)))
        fila[label_col] = target_label

    sinteticas = pl.DataFrame(filas, schema=df.schema)
    combinado = pl.concat([df, sinteticas], how="vertical_relaxed")
    idx = list(range(df.height, combinado.height))

    return PoisonSpec(
        df=combinado,
        poisoned_idx=idx,
        kind="synthetic",
        params={
            "n_rows": len(idx),
            "target_label": target_label,
            "source_label": source_label,
            "jitter": jitter,
        },
    )
