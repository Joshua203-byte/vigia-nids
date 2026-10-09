"""Checks de duplicados."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.checks.duplicates import (
    CrossSplitDuplicateCheck,
    ExactDuplicateCheck,
    NearDuplicateCheck,
)
from vigia.core.context import CheckSkipped


def test_duplicados_exactos(make_ctx):
    base = {"a": [1, 1, 2, 3], "b": [10, 10, 20, 30], "label": ["x", "x", "y", "y"]}
    findings = ExactDuplicateCheck().run(make_ctx(pl.DataFrame(base)))
    exact = [f for f in findings if f.check_id == "dup.exact"]
    assert len(exact) == 1
    assert exact[0].affected_rows == 1
    assert exact[0].metric["ratio"] == pytest.approx(0.25)


def test_sin_duplicados_no_reporta(clean_ctx):
    assert ExactDuplicateCheck().run(clean_ctx) == []


def test_clase_mayoritariamente_duplicada(make_ctx):
    """Los ataques DoS repetitivos hacen que el recall de esa clase no sea
    confiable: hay muchas filas pero pocos ejemplos distintos."""
    n = 40
    df = pl.DataFrame(
        {
            "a": [1] * n + list(range(n)),
            "label": ["DoS"] * n + ["BENIGN"] * n,
        }
    )
    findings = ExactDuplicateCheck().run(make_ctx(df))
    per_class = [f for f in findings if f.check_id == "dup.class_ratio"]
    assert len(per_class) == 1
    assert "DoS" in per_class[0].metric


def test_duplicado_cruzando_splits_es_critico(make_ctx):
    df = pl.DataFrame(
        {
            "a": [1, 2, 3, 1],
            "label": ["x", "y", "y", "x"],
            "split": ["train", "train", "train", "test"],
        }
    )
    findings = CrossSplitDuplicateCheck().run(make_ctx(df, split_col="split"))
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].affected_rows == 2  # la fila en train y su copia en test


def test_cross_split_ignora_filas_sin_split(make_ctx):
    """Una fila sin split no pertenece a ningún conjunto: no puede cruzar.

    Antes el nulo contaba como un split más y la copia en `None` de una fila
    de entrenamiento se reportaba como fuga crítica.
    """
    df = pl.DataFrame(
        {
            "a": [1, 1, 2, 3],
            "label": ["x", "x", "y", "y"],
            "split": ["train", None, "test", "train"],
        }
    )
    assert CrossSplitDuplicateCheck().run(make_ctx(df, split_col="split")) == []


def test_cross_split_reporta_pese_a_filas_sin_split(make_ctx):
    """El nulo no debe tapar un cruce real entre train y test."""
    df = pl.DataFrame(
        {
            "a": [1, 1, 1, 2],
            "label": ["x", "x", "x", "y"],
            "split": ["train", "test", None, "train"],
        }
    )
    findings = CrossSplitDuplicateCheck().run(make_ctx(df, split_col="split"))
    assert len(findings) == 1
    assert findings[0].affected_rows == 2  # la de train y la de test, no la nula
    assert findings[0].metric["n_unassigned"] == 1.0


def test_cross_split_se_salta_sin_columna_de_split(make_ctx):
    df = pl.DataFrame({"a": [1, 2], "label": ["x", "y"]})
    with pytest.raises(CheckSkipped):
        CrossSplitDuplicateCheck().run(make_ctx(df))


def test_cross_split_se_salta_con_un_solo_split(make_ctx):
    df = pl.DataFrame({"a": [1, 2], "label": ["x", "y"], "split": ["train", "train"]})
    with pytest.raises(CheckSkipped):
        CrossSplitDuplicateCheck().run(make_ctx(df, split_col="split"))


def test_casi_duplicados_por_ruido_de_precision(make_ctx):
    """Dos filas iguales salvo el último decimal de una tasa no son un
    duplicado exacto, pero un modelo las trata como el mismo ejemplo."""
    n_pad = 20
    df = pl.DataFrame(
        {
            "rate": [100.00001, 100.00002] + list(range(n_pad)),
            "b": [5.0, 5.0] + [float(i) for i in range(n_pad)],
            "label": ["x", "x"] + ["y"] * n_pad,
        }
    )
    findings = NearDuplicateCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].affected_rows == 2
    assert findings[0].auto_fix is None


def test_duplicados_exactos_no_cuentan_como_casi_duplicados(make_ctx):
    """dup.exact ya reporta las filas idénticas; dup.near no debe repetirlas."""
    df = pl.DataFrame({"a": [1, 1, 2, 3], "b": [10, 10, 20, 30], "label": ["x", "x", "y", "y"]})
    assert NearDuplicateCheck().run(make_ctx(df)) == []


def test_casi_duplicado_de_una_fila_repetida_se_ve(make_ctx):
    """Excluir *todas* las copias de un duplicado exacto dejaba sin pareja a su
    casi-duplicado: agregar una copia exacta hacía desaparecer el hallazgo.
    Es el caso del DoS repetitivo (AUDITORIA-1.0.md, SCI-08)."""
    pytest.importorskip("datasketch")
    # 60 columnas: una distinta da Jaccard 59/61 = 0,967, lejos del umbral 0,9
    # para que el LSH (probabilístico) no lo deje pasar por azar.
    cols = {f"c{i}": [float((j * 37 + i * 11) % 997) for j in range(60)] for i in range(60)}
    base = pl.DataFrame(cols)
    fila = base.row(0, named=True)
    casi = {**fila, "c0": fila["c0"] + 1}  # difiere en 1 de 60 columnas
    df = pl.concat([base, pl.DataFrame([fila]), pl.DataFrame([casi])])
    df = df.with_columns(pl.lit("x").alias("label"))

    findings = NearDuplicateCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].affected_rows == 2  # el representante y su casi-copia


def test_sin_casi_duplicados_no_reporta(clean_ctx):
    assert NearDuplicateCheck().run(clean_ctx) == []


def test_near_duplicate_se_salta_sin_columnas_de_caracteristicas(make_ctx):
    df = pl.DataFrame({"label": ["x", "y"]})
    with pytest.raises(CheckSkipped):
        NearDuplicateCheck().run(make_ctx(df))


def test_near_duplicate_respeta_el_umbral_configurado(make_ctx):
    """Con un umbral muy alto, filas parecidas pero no casi-idénticas no cuentan."""
    n_pad = 20
    df = pl.DataFrame(
        {
            "a": [1.0, 1.5] + [100.0 + i for i in range(n_pad)],
            "b": [1.0, 1.5] + [100.0 + i for i in range(n_pad)],
            "label": ["x", "x"] + ["y"] * n_pad,
        }
    )
    ctx = make_ctx(df, config={"near_duplicate_threshold": 0.98})
    assert NearDuplicateCheck().run(ctx) == []


def test_near_duplicate_se_salta_con_umbral_no_soportado_por_lsh(make_ctx):
    """A partir de ~0.99 el cálculo interno de bandas de MinHashLSH colapsa;
    tiene que salir como CheckSkipped, no como un ValueError de la librería."""
    df = pl.DataFrame({"a": [1.0, 2.0, 3.0], "label": ["x", "y", "y"]})
    ctx = make_ctx(df, config={"near_duplicate_threshold": 0.999})
    with pytest.raises(CheckSkipped):
        NearDuplicateCheck().run(ctx)


def test_minhash_bulk_da_las_mismas_firmas_que_update():
    """dup.near usa `MinHash.bulk` por velocidad; sus firmas tienen que ser las
    mismas que token por token, o los resultados cambiarian en silencio."""
    datasketch = pytest.importorskip("datasketch")
    from vigia.checks.duplicates import NearDuplicateCheck

    filas = [[f"c{i}={(i * j) % 7}".encode() for i in range(12)] for j in range(30)]
    por_lote = datasketch.MinHash.bulk(filas, num_perm=NearDuplicateCheck.NUM_PERM)
    for tokens, firma in zip(filas, por_lote, strict=True):
        uno_a_uno = datasketch.MinHash(num_perm=NearDuplicateCheck.NUM_PERM)
        for token in tokens:
            uno_a_uno.update(token)
        assert (uno_a_uno.hashvalues == firma.hashvalues).all()


def test_el_mismo_flujo_en_otra_ip_es_duplicado_si_la_ip_es_un_rol_declarado(make_ctx):
    """Con la IP en el hash, el mismo flujo visto desde otro host no se vería."""
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "bytes": [100, 100, 300],
            "label": ["x", "x", "y"],
        }
    )
    sin_rol = ExactDuplicateCheck().run(make_ctx(df))
    con_rol = ExactDuplicateCheck().run(make_ctx(df, declared_roles=frozenset({"src_ip"})))
    assert sin_rol == []
    assert [f.affected_rows for f in con_rol] == [1]


def _casi_duplicados(n_grupos: int, copias: int = 3) -> pl.DataFrame:
    """Grupos de `copias` filas casi iguales (una columna difiere en un detalle)."""
    filas = []
    for g in range(n_grupos):
        base = {f"c{j}": g * 100 + j for j in range(8)}
        for k in range(copias):
            filas.append({**base, "c7": base["c7"] + k * 0.00001, "label": "x" if g % 2 else "y"})
    return pl.DataFrame(filas)


def test_near_duplicate_sobre_el_limite_trabaja_con_una_muestra(make_ctx, monkeypatch):
    df = _casi_duplicados(400)
    monkeypatch.setattr(NearDuplicateCheck, "MAX_ROWS", 600)

    completo = NearDuplicateCheck().run(make_ctx(df, config={}))[0]
    monkeypatch.setattr(NearDuplicateCheck, "MAX_ROWS", 200_000)
    exacto = NearDuplicateCheck().run(make_ctx(df, config={}))[0]

    assert exacto.metric["n_evaluated"] == df.height
    assert "muestra" not in exacto.description
    # Con una muestra de la mitad no puede ver mas que el total, y lo declara.
    assert completo.metric["n_evaluated"] == 600
    assert completo.metric["n_affected"] <= exacto.metric["n_affected"]
    assert "cota inferior" in completo.description
    assert 0 < completo.metric["ratio"] <= 1


def test_near_duplicate_con_muestra_es_reproducible(make_ctx, monkeypatch):
    df = _casi_duplicados(400)
    monkeypatch.setattr(NearDuplicateCheck, "MAX_ROWS", 600)
    a = NearDuplicateCheck().run(make_ctx(df, seed=3))[0].metric
    b = NearDuplicateCheck().run(make_ctx(df, seed=3))[0].metric
    assert a == b
