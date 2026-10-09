"""Checks de validez básica."""

from __future__ import annotations

import math

import polars as pl

from vigia.checks.validity import (
    ColumnHygieneCheck,
    ConstantCheck,
    ImpossibleValuesCheck,
    NanInfCheck,
)


def test_nan_inf_detecta_infinitos(make_ctx):
    df = pl.DataFrame(
        {
            "flow_bytes_s": [1.0, 2.0, math.inf, float("nan"), 5.0],
            "label": ["a", "b", "a", "b", "a"],
        }
    )
    findings = NanInfCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["inf"] == 1.0
    assert findings[0].metric["nan"] == 1.0
    assert findings[0].severity == "high"  # un infinito siempre es grave


def test_nan_inf_agrupa_columnas_con_el_mismo_recuento(make_ctx):
    """Muchas columnas rotas en las mismas filas son UN problema, no muchos.

    En CIC-IDS2017 son 80 columnas con 288.602 nulos cada una, todas por las
    mismas filas sin etiqueta. Un hallazgo por columna vuelve ilegible el
    reporte y esconde los hallazgos críticos.
    """
    df = pl.DataFrame(
        {
            "a": [1.0, None, 3.0],
            "b": [4.0, None, 6.0],
            "c": [7.0, None, 9.0],
            "d": [1.0, 2.0, 3.0],  # sana
            "label": ["x", "y", "x"],
        }
    )
    findings = NanInfCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_columns"] == 3.0
    assert "3 columnas" in findings[0].title
    assert "causa común" in findings[0].description


def test_nan_inf_no_agrupa_recuentos_distintos(make_ctx):
    """Dos columnas con distinta cantidad de fallas son problemas separados."""
    df = pl.DataFrame(
        {
            "a": [1.0, None, 3.0, 4.0],
            "b": [None, None, 6.0, 7.0],
            "label": ["x", "y", "x", "y"],
        }
    )
    findings = NanInfCheck().run(make_ctx(df))
    assert len(findings) == 2
    assert all(f.metric["n_columns"] == 1.0 for f in findings)


def test_nan_inf_silencioso_en_dataset_limpio(clean_ctx):
    assert NanInfCheck().run(clean_ctx) == []


def test_constant_detecta_columna_de_un_solo_valor(make_ctx):
    df = pl.DataFrame({"x": [1, 2, 3], "siempre_cero": [0, 0, 0], "label": ["a", "b", "a"]})
    findings = ConstantCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_constant_cols"] == 1.0


def test_constant_ignora_los_nulos(make_ctx):
    """`n_unique` cuenta el nulo como un valor: [7, 7, 7, None] daba 2 y la
    columna no se reportaba, aunque el comentario decía "ignorando nulos"
    (AUDITORIA-1.0.md, COR-12). Una columna toda nula también es constante."""
    df = pl.DataFrame(
        {
            "casi": [7, 7, 7, None],
            "vacia": pl.Series([None] * 4, dtype=pl.Int64),
            "varia": [1, 2, 3, None],
            "label": ["a", "b", "a", "b"],
        }
    )
    findings = ConstantCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_constant_cols"] == 2.0
    assert {e["columna"] for e in findings[0].examples} == {"casi", "vacia"}


def test_column_names_detecta_espacios(make_ctx):
    """`vigia.load` normaliza los nombres, pero el check protege a quien arma
    el contexto a mano o lee con `strip_names=False`."""
    df = pl.DataFrame({" Destination Port": [80, 443], "label": ["a", "b"]})
    findings = ColumnHygieneCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].auto_fix == "strip_column_names"


def test_impossible_detecta_puerto_fuera_de_rango(make_ctx):
    df = pl.DataFrame({"dst_port": [80, 443, 70000, -1], "label": ["a", "b", "a", "b"]})
    findings = ImpossibleValuesCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_invalid"] == 2.0
    assert findings[0].metric["observed_max"] == 70000.0
    assert findings[0].metric["max_allowed"] == 65535


def test_impossible_ignora_el_centinela_menos_uno(make_ctx):
    """En CICFlowMeter, -1 en las ventanas TCP significa "no aplica".

    En CIC-IDS2017 son 224.495 filas del lunes: tratarlas como valores
    imposibles sepulta los desbordamientos reales bajo falsos positivos.
    """
    df = pl.DataFrame(
        {
            "Init_Win_bytes_forward": [8192, -1, -1, 65535],
            "label": ["a", "b", "a", "b"],
        }
    )
    assert ImpossibleValuesCheck().run(make_ctx(df)) == []


def test_impossible_reporta_negativos_reales_pese_al_centinela(make_ctx):
    """Un -1 se perdona; un desbordamiento de entero no."""
    df = pl.DataFrame(
        {
            "Init_Win_bytes_forward": [8192, -1, -167770490, 65535],
            "label": ["a", "b", "a", "b"],
        }
    )
    findings = ImpossibleValuesCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_invalid"] == 1.0


def test_impossible_no_perdona_menos_uno_en_otras_columnas(make_ctx):
    """El centinela vale solo donde CICFlowMeter lo documenta."""
    df = pl.DataFrame({"Flow Duration": [100, -1, 200], "label": ["a", "b", "a"]})
    findings = ImpossibleValuesCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].metric["n_invalid"] == 1.0


def test_impossible_reconoce_el_nombre_de_la_version_corregida(make_ctx):
    """La versión corregida renombra la columna a 'Init Fwd Win Bytes'."""
    df = pl.DataFrame({"Init Fwd Win Bytes": [8192, -1, 65535], "label": ["a", "b", "a"]})
    assert ImpossibleValuesCheck().run(make_ctx(df)) == []


def test_impossible_omite_max_allowed_cuando_no_hay_cota(make_ctx):
    """Sin cota superior no se emite la clave: un -1.0 de centinela confunde."""
    df = pl.DataFrame({"flow_duration": [10, -5], "label": ["a", "b"]})
    findings = ImpossibleValuesCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert "max_allowed" not in findings[0].metric
    assert findings[0].metric["min_allowed"] == 0


def test_impossible_no_falla_con_enteros_chicos_en_columnas_de_puerto(make_ctx):
    """`is_sm_ips_ports` (UNSW-NB15) es un indicador Int8 cuyo nombre contiene
    'port': compararlo con 65535 desbordaba el tipo y tiraba el check entero."""
    df = pl.DataFrame(
        {
            "is_sm_ips_ports": pl.Series([0, 1, 0, 1], dtype=pl.Int8),
            "dsport": pl.Series([80, 443, 70000, 22], dtype=pl.Int32),
            "label": ["a", "b", "a", "b"],
        }
    )

    findings = ImpossibleValuesCheck().run(make_ctx(df))

    assert len(findings) == 1  # solo 'dsport' (70000 > 65535)
    assert "dsport" in findings[0].title
