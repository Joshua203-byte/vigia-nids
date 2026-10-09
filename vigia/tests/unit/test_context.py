"""AuditContext: selección de columnas y derivados cacheados."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.core.context import AuditContext, CheckSkipped


def test_feature_cols_excluye_etiqueta_y_split(make_ctx):
    df = pl.DataFrame({"bytes": [1, 2], "label": ["a", "b"], "split": ["train", "test"]})
    ctx = make_ctx(df, split_col="split")
    assert ctx.feature_cols == ["bytes"]


def test_feature_cols_excluye_columnas_internas(make_ctx):
    """`__source_file` la agrega el lector, no viene del dataset.

    Si entrara al hash de fila, dos flujos idénticos capturados en archivos
    distintos dejarían de contarse como duplicados.
    """
    df = pl.DataFrame(
        {"bytes": [1, 2], "label": ["a", "b"], "__source_file": ["lun.csv", "mar.csv"]}
    )
    assert make_ctx(df).feature_cols == ["bytes"]


def test_filas_iguales_en_archivos_distintos_son_duplicados(make_ctx):
    from vigia.checks.duplicates import ExactDuplicateCheck

    df = pl.DataFrame(
        {
            "bytes": [100, 100],
            "label": ["DoS", "DoS"],
            "__source_file": ["lunes.csv", "martes.csv"],
        }
    )
    findings = ExactDuplicateCheck().run(make_ctx(df))
    exact = [f for f in findings if f.check_id == "dup.exact"]
    assert len(exact) == 1
    assert exact[0].affected_rows == 1


def test_numeric_cols_solo_numericas(make_ctx):
    df = pl.DataFrame({"bytes": [1, 2], "host": ["a", "b"], "label": ["x", "y"]})
    assert make_ctx(df).numeric_cols == ["bytes"]


def test_require_lanza_check_skipped(make_ctx):
    ctx = make_ctx(pl.DataFrame({"a": [1], "label": ["x"]}))
    with pytest.raises(CheckSkipped, match="split_col"):
        ctx.require("split_col")


def test_option_devuelve_el_default(make_ctx):
    ctx = make_ctx(pl.DataFrame({"a": [1], "label": ["x"]}))
    assert ctx.option("umbral", 0.9) == 0.9


def test_option_lee_la_config():
    df = pl.DataFrame({"a": [1], "label": ["x"]})
    ctx = AuditContext(df=df, label_col="label", config={"umbral": 0.5})
    assert ctx.option("umbral", 0.9) == 0.5


def test_hash_de_cero_columnas_conserva_la_altura(make_ctx):
    """Una Serie vacía no se puede combinar con el DataFrame.

    Regresión: con un dataset de solo la columna de etiqueta, `labels.conflict`
    y los checks de duplicados morían con ShapeError.
    """
    from vigia.core.hashing import row_hashes

    df = pl.DataFrame({"label": ["x", "y", "x"]})
    assert row_hashes(df, []).len() == 3


def test_checks_de_hash_se_saltan_sin_caracteristicas(make_ctx):
    """Sin características, "duplicado" y "conflicto" no significan nada."""
    from vigia.checks.duplicates import ExactDuplicateCheck
    from vigia.checks.labels import LabelConflictCheck

    ctx = make_ctx(pl.DataFrame({"label": ["x", "y", "x"]}))
    for check in (ExactDuplicateCheck(), LabelConflictCheck()):
        with pytest.raises(CheckSkipped, match="características"):
            check.run(ctx)


# --- Preparación para los módulos 2 y 3 ---------------------------------------


def test_contexto_acepta_un_dataset_de_referencia(make_ctx):
    """El módulo de deriva compara dos datasets, no uno solo."""
    actual = pl.DataFrame({"a": [1, 2], "label": ["x", "y"]})
    ref = pl.DataFrame({"a": [10, 20], "label": ["x", "y"]})
    ctx = make_ctx(actual, reference=ref)
    assert ctx.reference is not None
    assert ctx.reference.height == 2


def test_require_reference_se_salta_sin_referencia(make_ctx):
    ctx = make_ctx(pl.DataFrame({"a": [1], "label": ["x"]}))
    with pytest.raises(CheckSkipped, match="reference"):
        ctx.require("reference")


def test_shared_comparte_resultados_caros_entre_checks(make_ctx):
    """Tres detectores de envenenamiento usan el mismo modelo base."""
    ctx = make_ctx(pl.DataFrame({"a": [1], "label": ["x"]}))
    ctx.shared["modelo_base"] = "entrenado una vez"
    assert ctx.shared["modelo_base"] == "entrenado una vez"
    # Es el mismo diccionario en cada acceso, no una copia nueva.
    assert ctx.shared is ctx.shared
