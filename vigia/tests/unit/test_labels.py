"""Checks de etiquetas."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.checks.labels import (
    LabelConflictCheck,
    LabelImbalanceCheck,
    LabelTaxonomyCheck,
)
from vigia.core.context import CheckSkipped


def test_conflicto_mismas_caracteristicas_distinta_etiqueta(make_ctx):
    df = pl.DataFrame(
        {
            "a": [1, 1, 2, 3],
            "b": [10, 10, 20, 30],
            "label": ["BENIGN", "DDoS", "BENIGN", "BENIGN"],
        }
    )
    findings = LabelConflictCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_conflict_groups"] == 1.0
    assert findings[0].affected_rows == 2
    assert "BENIGN / DDoS" in findings[0].examples[0]["etiquetas_en_conflicto"]


def test_sin_conflictos_no_reporta(make_ctx):
    df = pl.DataFrame({"a": [1, 2, 3], "label": ["x", "y", "x"]})
    assert LabelConflictCheck().run(make_ctx(df)) == []


def test_duplicado_con_la_misma_etiqueta_no_es_conflicto(make_ctx):
    """Una fila repetida con la misma etiqueta es un duplicado, no un conflicto."""
    df = pl.DataFrame({"a": [1, 1, 2], "label": ["x", "x", "y"]})
    assert LabelConflictCheck().run(make_ctx(df)) == []


def test_conflicto_es_critico_cuando_supera_el_uno_por_ciento(make_ctx):
    df = pl.DataFrame(
        {
            "a": [1, 1] + list(range(2, 50)),
            "label": ["x", "y"] + ["z"] * 48,
        }
    )
    findings = LabelConflictCheck().run(make_ctx(df))
    assert findings[0].severity == "critical"


def test_conflicto_con_etiquetas_nulas_no_crashea(make_ctx):
    """Una fila sin etiqueta con las mismas características que una etiquetada
    hacía fallar el check con `TypeError` al unir las etiquetas del grupo
    (AUDITORIA-1.0.md, COR-03). Sin etiqueta no hay conflicto: no hay dos
    etiquetas que se contradigan. Un conflicto real se sigue viendo."""
    from vigia.checks.labels import LabelConflictCheck

    df = pl.DataFrame(
        {
            "f1": [1.0, 1.0, 2.0, 3.0, 3.0] * 10,
            "f2": [5, 5, 6, 7, 7] * 10,
            "label": ["BENIGN", None, "DoS", "DoS", "BENIGN"] * 10,
        }
    )
    findings = LabelConflictCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_conflict_groups"] == 1.0  # solo (3.0, 7)
    assert findings[0].examples[0]["etiquetas_en_conflicto"] == "BENIGN / DoS"


def test_taxonomia_detecta_variantes_de_escritura(make_ctx):
    df = pl.DataFrame(
        {
            "a": list(range(6)),
            "label": ["DoS Hulk", "DoS-Hulk", "dos hulk", "BENIGN", "BENIGN", "BENIGN"],
        }
    )
    findings = LabelTaxonomyCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_clases_afectadas"] == 1.0
    assert findings[0].auto_fix == "normalize_labels"


def test_taxonomia_no_confunde_clases_distintas(make_ctx):
    df = pl.DataFrame(
        {
            "a": [1, 2, 3],
            "label": ["DoS Hulk", "DoS GoldenEye", "BENIGN"],
        }
    )
    assert LabelTaxonomyCheck().run(make_ctx(df)) == []


def test_desbalance_detecta_clases_diminutas(make_ctx):
    """El caso real: Heartbleed con 11 ejemplos entre 692.703 filas."""
    df = pl.DataFrame(
        {
            "a": list(range(2010)),
            "label": ["BENIGN"] * 2000 + ["Heartbleed"] * 10,
        }
    )
    findings = LabelImbalanceCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["min_ejemplos"] == 10.0
    assert findings[0].metric["ratio_desbalance"] == pytest.approx(200.0)


def test_desbalance_no_dispara_en_datasets_chicos(make_ctx):
    """Con 120 filas, "menos de 100 ejemplos" describe a casi toda clase.

    El umbral se acota a una fracción del dataset para que el hallazgo hable
    de clases desproporcionadamente raras y no del tamaño del archivo.
    """
    df = pl.DataFrame({"a": list(range(120)), "label": ["x"] * 68 + ["y"] * 52})
    assert LabelImbalanceCheck().run(make_ctx(df)) == []


def test_desbalance_respeta_el_umbral_configurado(make_ctx):
    df = pl.DataFrame({"a": list(range(60)), "label": ["x"] * 50 + ["y"] * 10})
    ctx = make_ctx(df, config={"min_class_examples": 5})
    assert LabelImbalanceCheck().run(ctx) == []


def test_desbalance_se_salta_con_una_sola_clase(make_ctx):
    df = pl.DataFrame({"a": [1, 2], "label": ["x", "x"]})
    with pytest.raises(CheckSkipped):
        LabelImbalanceCheck().run(make_ctx(df))
