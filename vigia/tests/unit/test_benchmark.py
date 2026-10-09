"""Comparación antes/después (R9)."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.benchmark import BenchmarkUnavailable, compare, evaluate

pytest.importorskip("lightgbm")
pytest.importorskip("sklearn")


def _dataset(n: int = 400, *, con_atajo: bool = False) -> pl.DataFrame:
    """Dos clases separables, con la opción de sembrar una columna delatora."""
    filas = {
        "bytes_fwd": [],
        "duration": [],
        "label": [],
        "split": [],
    }
    if con_atajo:
        filas["Source IP"] = []

    for i in range(n):
        es_ataque = i % 2 == 0
        base = 100.0 if es_ataque else 10.0
        filas["bytes_fwd"].append(base + (i % 9) * 0.5)
        filas["duration"].append(base * 1.5 + (i % 7) * 0.3)
        filas["label"].append("attack" if es_ataque else "BENIGN")
        filas["split"].append("train" if i < n * 0.7 else "test")
        if con_atajo:
            filas["Source IP"].append("10.0.0.1" if es_ataque else "10.0.0.2")
    return pl.DataFrame(filas)


def test_evaluate_devuelve_metricas(make_ctx):
    m = evaluate(make_ctx(_dataset(), split_col="split"))
    assert 0.0 <= m.f1_macro <= 1.0
    assert m.n_train > 0 and m.n_test > 0
    assert set(m.per_class_recall) == {"attack", "BENIGN"}


def test_cuenta_los_falsos_positivos_sobre_benignos(make_ctx):
    m = evaluate(make_ctx(_dataset(), split_col="split"))
    assert m.fp_per_10k_benign is not None
    assert m.fp_per_10k_benign >= 0


def test_descarta_las_filas_sin_etiqueta(make_ctx):
    """CIC-IDS2017 tiene 288.602: sin descartarlas el entrenamiento falla."""
    df = _dataset(200).with_columns(
        pl.when(pl.int_range(pl.len()) < 20).then(None).otherwise(pl.col("label")).alias("label")
    )
    m = evaluate(make_ctx(df, split_col="split"))
    assert m.n_sin_etiqueta == 20
    assert m.n_train + m.n_test == 180


def test_usa_tambien_las_columnas_categoricas(make_ctx):
    """El atajo más grave de CIC-IDS2017 vive en `Source IP`, que es texto.

    Si el benchmark solo mirara columnas numéricas, quitarla no cambiaría
    nada y la comparación sería vacía por construcción.
    """
    con = evaluate(make_ctx(_dataset(con_atajo=True), split_col="split"))
    sin = evaluate(make_ctx(_dataset(con_atajo=False), split_col="split"))
    assert con.n_features == sin.n_features + 1


def test_compare_aplica_las_correcciones(make_ctx):
    c = compare(make_ctx(_dataset(con_atajo=True), split_col="split"), ["drop_identifiers"])
    assert c.fixes_applied == ["drop_identifiers"]
    assert c.after.n_features < c.before.n_features
    assert "F1 macro" in c.summary()


def test_compare_respeta_los_roles_declarados():
    """`compare` reconstruia el contexto sin `declared_roles`: `drop_duplicates`
    volvia a meter la hora en la clave y dejaba los duplicados cruzados en el
    "despues" (AUDITORIA-1.0.md, COR-01)."""
    from vigia.core.context import AuditContext

    n = 400
    df = pl.DataFrame(
        {
            "Timestamp": [f"2017-07-03 10:{i % 60:02d}:{(i * 7) % 60:02d}" for i in range(n)],
            "bytes": [i % 5 for i in range(n)],
            "pkts": [i % 3 for i in range(n)],
            "Label": ["BENIGN" if i % 2 else "DoS" for i in range(n)],
            "split": ["train" if i % 10 < 7 else "test" for i in range(n)],
        }
    )
    ctx = AuditContext(
        df=df, label_col="Label", split_col="split", declared_roles=frozenset({"Timestamp"})
    )
    c = compare(ctx, ["drop_duplicates"])
    unicas = df.unique(subset=["bytes", "pkts", "Label"]).height
    assert c.after.n_train + c.after.n_test == unicas


def _solapado(n: int = 4000) -> pl.DataFrame:
    """Dos clases solapadas, sin ruido de etiqueta ni duplicados."""
    import numpy as np

    rng = np.random.default_rng(1)
    y = rng.choice(["BENIGN", "ATTACK"], n)
    f1 = np.where(y == "ATTACK", rng.normal(1.0, 1, n), rng.normal(0, 1, n))
    f2 = np.where(y == "ATTACK", rng.normal(1.0, 1, n), rng.normal(0, 1, n))
    split = np.where(rng.uniform(size=n) < 0.7, "train", "test")
    return pl.DataFrame({"f1": f1, "f2": f2, "Label": y, "split": split})


def test_compare_con_cuarentena_no_infla_el_f1_sobre_datos_sin_ruido():
    """`quarantine_noise` aparta las filas que el modelo auxiliar predice mal.
    Aplicada tambien al test, las sacaba de la evaluacion y el F1 subia 15
    puntos sobre datos sin ruido alguno (AUDITORIA-1.0.md, SCI-04)."""
    from vigia.core.context import AuditContext

    df = _solapado()
    c = compare(AuditContext(df=df, label_col="Label", split_col="split"), ["quarantine_noise"])
    assert c.fixes_applied == ["quarantine_noise"]
    assert c.after.n_test == c.before.n_test
    assert c.f1_delta < 0.03, c.summary()


def test_compare_avisa_cuando_cambia_el_conjunto_de_prueba():
    """`drop_duplicates` saca del test copias de filas de entrenamiento: es
    legitimo (quita memorizacion), pero el resumen tiene que decirlo."""
    from vigia.core.context import AuditContext

    df = _solapado(1000)
    copias = (
        df.filter(pl.col("split") == "train").head(20).with_columns(pl.lit("test").alias("split"))
    )
    df = pl.concat([df, copias])
    c = compare(AuditContext(df=df, label_col="Label", split_col="split"), ["drop_duplicates"])
    assert c.test_changed
    assert "prueba" in c.summary()
    assert c.to_dict()["test_changed"] is True


def test_compare_ignora_una_correccion_que_no_aplica(make_ctx):
    c = compare(make_ctx(_dataset(), split_col="split"), ["drop_identifiers"])
    assert c.fixes_applied == []


def test_se_niega_sin_columna_de_split(make_ctx):
    with pytest.raises(BenchmarkUnavailable, match="split"):
        evaluate(make_ctx(_dataset().drop("split")))


def test_se_niega_con_una_sola_clase(make_ctx):
    df = _dataset(100).with_columns(pl.lit("BENIGN").alias("label"))
    with pytest.raises(BenchmarkUnavailable, match="una sola clase"):
        evaluate(make_ctx(df, split_col="split"))
