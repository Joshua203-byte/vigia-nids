"""Detección de ruido de etiqueta (R7)."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.checks.label_noise import LabelNoiseCheck, max_overestimate
from vigia.core.context import CheckSkipped

pytest.importorskip("cleanlab")
pytest.importorskip("sklearn")


def _dataset_con_ruido(n: int = 300, n_flipped: int = 15) -> pl.DataFrame:
    """Dos nubes bien separadas, con algunas etiquetas invertidas a propósito."""
    labels, f1, f2 = [], [], []
    for i in range(n):
        es_ataque = i % 2 == 0
        labels.append("attack" if es_ataque else "benign")
        # Clases linealmente separables: cualquier error viene de la etiqueta.
        base = 100.0 if es_ataque else 10.0
        f1.append(base + (i % 7) * 0.4)
        f2.append(base * 2 + (i % 5) * 0.3)

    # Se invierten las primeras n_flipped etiquetas: ese es el ruido a detectar.
    for i in range(n_flipped):
        labels[i] = "benign" if labels[i] == "attack" else "attack"

    return pl.DataFrame({"bytes_fwd": f1, "bytes_bwd": f2, "label": labels})


def test_detecta_etiquetas_invertidas(make_ctx):
    findings = LabelNoiseCheck().run(make_ctx(_dataset_con_ruido()))
    assert len(findings) == 1
    # No se exige el número exacto: cleanlab estima, no cuenta.
    assert findings[0].metric["n_sospechosas"] >= 5
    assert findings[0].auto_fix == "quarantine_noise"


def test_el_ejemplo_nombra_la_etiqueta_sugerida(make_ctx):
    findings = LabelNoiseCheck().run(make_ctx(_dataset_con_ruido()))
    ej = findings[0].examples[0]
    assert ej["etiqueta_actual"] != ej["sugerida_por_el_modelo"]


def test_dataset_sin_ruido_no_reporta(make_ctx):
    """Clases separables y bien etiquetadas: no debería haber sospechosas."""
    findings = LabelNoiseCheck().run(make_ctx(_dataset_con_ruido(n_flipped=0)))
    assert findings == []


def test_ignora_las_columnas_identificadoras(make_ctx):
    """Con la IP disponible el modelo acierta memorizando y no ve el ruido.

    Es la advertencia explícita de la sección 8.3 del documento de diseño.
    """
    df = _dataset_con_ruido().with_columns(
        # Una IP que coincide perfectamente con la etiqueta ruidosa: si el
        # check la usara, no encontraría nada que corregir.
        pl.col("label")
        .map_elements(lambda v: "10.0.0.1" if v == "attack" else "10.0.0.2", return_dtype=pl.Utf8)
        .alias("Source IP")
    )
    findings = LabelNoiseCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_columnas_usadas"] == 2.0  # bytes_fwd y bytes_bwd


def test_se_salta_cuando_las_columnas_no_predicen_la_etiqueta(make_ctx):
    """Sin señal, lo que el modelo no acierta no es ruido de etiqueta.

    Regresión: sobre el dataset de control —características deliberadamente
    independientes de la etiqueta— el check reportaba 37,5 % de ruido
    inexistente, porque cleanlab marca toda fila que el modelo no predice.
    """
    n = 120
    df = pl.DataFrame(
        {
            "duration": [round(0.5 + i * 0.37, 2) for i in range(n)],
            "bytes_fwd": [100 + i * 7 for i in range(n)],
            "pkts_fwd": [1 + (i * 3) % 40 for i in range(n)],
            "label": ["attack" if (i * 13) % 7 < 3 else "benign" for i in range(n)],
        }
    )
    with pytest.raises(CheckSkipped, match="no predicen la etiqueta"):
        LabelNoiseCheck().run(make_ctx(df))


def test_corre_con_clase_mayoritaria_del_96_por_ciento(make_ctx):
    """Con la mayoritaria >= 95 %, `exactitud >= base + 0,05` exige más de 1,0:
    el check no podía correr nunca, justo en la proporción del tráfico real
    (AUDITORIA-1.0.md, SCI-06). Clases bien separadas y 2 % de ruido inyectado."""
    import numpy as np

    rng = np.random.default_rng(0)
    n = 8000
    y = np.where(rng.uniform(size=n) < 0.96, "BENIGN", "ATTACK")
    f1 = np.where(y == "ATTACK", rng.normal(4, 1, n), rng.normal(0, 1, n))
    f2 = np.where(y == "ATTACK", rng.normal(4, 1, n), rng.normal(0, 1, n))
    flip = rng.choice(n, int(n * 0.02), replace=False)
    y[flip] = np.where(y[flip] == "BENIGN", "ATTACK", "BENIGN")
    df = pl.DataFrame({"f1": f1, "f2": f2, "label": y})

    findings = LabelNoiseCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert 0.01 <= findings[0].metric["ratio"] <= 0.04


def test_reporta_la_habilidad_del_modelo_auxiliar(make_ctx):
    """Quien lea el hallazgo tiene que poder juzgar cuánto confiar en él."""
    findings = LabelNoiseCheck().run(make_ctx(_dataset_con_ruido()))
    m = findings[0].metric
    assert m["exactitud_modelo_auxiliar"] > m["exactitud_clase_mayoritaria"]


def test_se_salta_sin_columnas_utiles(make_ctx):
    df = pl.DataFrame({"Source IP": ["10.0.0.1", "10.0.0.2"], "label": ["a", "b"]})
    with pytest.raises(CheckSkipped, match="columnas numéricas"):
        LabelNoiseCheck().run(make_ctx(df))


def test_se_salta_con_clases_demasiado_raras(make_ctx):
    df = pl.DataFrame(
        {
            "a": [1.0, 2.0, 3.0, 4.0],
            "b": [5.0, 6.0, 7.0, 8.0],
            "label": ["x", "x", "y", "z"],
        }
    )
    with pytest.raises(CheckSkipped, match="2 clases"):
        LabelNoiseCheck().run(make_ctx(df))


def test_cleanlab_se_llama_con_un_solo_proceso(make_ctx, monkeypatch):
    """Por defecto cleanlab abre un pool de procesos; en Windows eso relanza el
    script que usa Vigia como libreria, en cadena, si no tiene la guarda
    `if __name__ == "__main__"`."""
    import cleanlab.filter

    llamadas: list[dict] = []
    original = cleanlab.filter.find_label_issues

    def espia(*args, **kwargs):
        llamadas.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(cleanlab.filter, "find_label_issues", espia)

    LabelNoiseCheck().run(make_ctx(_dataset_con_ruido()))

    assert llamadas
    assert llamadas[0].get("n_jobs") == 1


def test_calla_por_debajo_del_umbral_minimo(make_ctx):
    """Un puñado de filas marcadas sobre cientos no vale una alarma."""
    ctx = make_ctx(_dataset_con_ruido())
    assert len(LabelNoiseCheck().run(ctx)) == 1
    ctx.config["noise_min_ratio"] = 0.99
    assert LabelNoiseCheck().run(ctx) == []


@pytest.mark.parametrize(
    ("exactitud", "cota"),
    [(0.999, 0.01), (0.97, 0.01), (0.95, 0.035), (0.90, 0.035), (0.85, 0.085), (0.70, 0.15)],
)
def test_la_cota_de_sobreestimacion_crece_cuando_baja_la_exactitud(exactitud, cota):
    assert max_overestimate(exactitud) == cota


def test_el_hallazgo_declara_cuanto_puede_sobreestimar(make_ctx):
    ctx = make_ctx(_dataset_con_ruido())
    ctx.config["noise_min_ratio"] = 0
    metric = LabelNoiseCheck().run(ctx)[0].metric
    assert metric["sobreestimacion_maxima_observada"] == max_overestimate(
        metric["exactitud_modelo_auxiliar"]
    )
