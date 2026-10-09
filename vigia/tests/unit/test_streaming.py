"""Modo streaming: checks de duplicados y validez sobre un archivo, sin
cargarlo entero en memoria (docs/PLAN.md, fase 1.5)."""

from __future__ import annotations

import math

import polars as pl
import pytest

from vigia.core.streaming import STREAMING_CHECKS, run_streaming_audit


def _write(df: pl.DataFrame, path, fmt: str = "csv"):
    if fmt == "parquet":
        df.write_parquet(path)
    else:
        df.write_csv(path)
    return path


def test_duplicados_exactos_en_streaming(tmp_path):
    df = pl.DataFrame({"a": [1, 1, 2, 3], "b": [10, 10, 20, 30], "label": ["x", "x", "y", "y"]})
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label")
    exact = [f for f in report.findings if f.check_id == "dup.exact"]
    assert len(exact) == 1
    assert exact[0].affected_rows == 1
    assert exact[0].metric["ratio"] == pytest.approx(0.25)


def test_sin_duplicados_no_reporta_en_streaming(tmp_path):
    df = pl.DataFrame({"a": [1, 2, 3, 4], "label": ["x", "y", "x", "y"]})
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label")
    assert [f for f in report.findings if f.check_id == "dup.exact"] == []


def test_duplicado_cruzando_splits_en_streaming(tmp_path):
    df = pl.DataFrame(
        {
            "a": [1, 2, 3, 1],
            "label": ["x", "y", "y", "x"],
            "split": ["train", "train", "train", "test"],
        }
    )
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label", split_col="split")
    crossing = [f for f in report.findings if f.check_id == "dup.cross_split"]
    assert len(crossing) == 1
    assert crossing[0].severity == "critical"
    assert crossing[0].affected_rows == 2


def test_cross_split_sin_columna_split_no_corre(tmp_path):
    df = pl.DataFrame({"a": [1, 1], "label": ["x", "x"]})
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label")
    assert [f for f in report.findings if f.check_id == "dup.cross_split"] == []


def test_nan_inf_en_streaming(tmp_path):
    df = pl.DataFrame(
        {
            "rate": [1.0, math.inf, 2.0, 3.0],
            "label": ["a", "b", "c", "d"],
        }
    )
    p = _write(df, tmp_path / "d.parquet", fmt="parquet")

    report = run_streaming_audit(p, label_col="label")
    nan_inf = [f for f in report.findings if f.check_id == "validity.nan_inf"]
    assert len(nan_inf) == 1
    assert nan_inf[0].metric["inf"] == 1.0
    assert nan_inf[0].severity == "high"


def test_columna_constante_en_streaming(tmp_path):
    df = pl.DataFrame({"a": [1, 2, 3], "flag": [7, 7, 7], "label": ["x", "y", "z"]})
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label")
    constant = [f for f in report.findings if f.check_id == "validity.constant"]
    assert len(constant) == 1
    assert "flag" in constant[0].description


def test_columna_constante_con_nulos_en_streaming(tmp_path):
    """El mismo criterio que el modo normal: los nulos no cuentan como valor
    (AUDITORIA-1.0.md, COR-12)."""
    df = pl.DataFrame({"a": [1, 2, 3, 4], "casi": [7, 7, 7, None], "label": list("xyzw")})
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label")
    constant = [f for f in report.findings if f.check_id == "validity.constant"]
    assert len(constant) == 1
    assert "casi" in constant[0].description


def test_checks_no_streameables_quedan_en_skipped(tmp_path):
    # Con columna de split, para que dup.cross_split corra: sin ella ahora figura
    # como saltado (antes callaba, ver test_streaming_dice_que_dup_cross_split_no_corrio).
    df = pl.DataFrame(
        {"a": [1, 2, 3], "label": ["x", "y", "z"], "split": ["train", "test", "train"]}
    )
    p = _write(df, tmp_path / "d.csv")

    report = run_streaming_audit(p, label_col="label", split_col="split")
    # Cada check no-streaming del auditor debe quedar explícitamente saltado,
    # nunca ausente sin más: es lo que evita que el semáforo mienta.
    assert "labels.noise" in report.skipped
    assert "shortcut.single_feature" in report.skipped
    assert "streaming" in report.skipped["labels.noise"]
    for streaming_id in STREAMING_CHECKS:
        assert streaming_id not in report.skipped


def test_formato_no_soportado_lanza_error(tmp_path):
    p = tmp_path / "d.json"
    p.write_text("{}")
    with pytest.raises(ValueError, match="streaming"):
        run_streaming_audit(p)


def test_equivalente_al_modo_eager(tmp_path):
    """El resultado de streaming tiene que coincidir con el de los checks
    normales sobre el mismo dataset, no solo parecerse."""
    from vigia.checks.duplicates import CrossSplitDuplicateCheck, ExactDuplicateCheck
    from vigia.core.context import AuditContext

    df = pl.DataFrame(
        {
            "a": [1.0, 1.0, 2.0, 3.0, 3.0, 4.0],
            "b": ["x", "x", "y", "z", "z", "w"],
            "label": ["BENIGN", "BENIGN", "BENIGN", "ATTACK", "ATTACK", "BENIGN"],
            "split": ["train", "test", "train", "train", "test", "train"],
        }
    )
    p = _write(df, tmp_path / "d.csv")

    eager_ctx = AuditContext(df=df, label_col="label", split_col="split")
    eager_exact = ExactDuplicateCheck().run(eager_ctx)
    eager_cross = CrossSplitDuplicateCheck().run(eager_ctx)

    report = run_streaming_audit(p, label_col="label", split_col="split")
    stream_exact = [f for f in report.findings if f.check_id == "dup.exact"]
    stream_cross = [f for f in report.findings if f.check_id == "dup.cross_split"]

    assert [f.affected_rows for f in stream_exact] == [
        f.affected_rows for f in eager_exact if f.check_id == "dup.exact"
    ]
    assert [f.affected_rows for f in stream_cross] == [f.affected_rows for f in eager_cross]


def _csv_estilo_cicflowmeter(tmp_path, n: int = 1000):
    """Nombres con espacio inicial, como los CSV de CICFlowMeter, y valores que
    se repiten para que haya duplicados."""
    import random

    r = random.Random(3)
    df = pl.DataFrame(
        {
            " Label": [r.choice(["BENIGN", "DoS"]) for _ in range(n)],
            " split": [r.choice(["train", "test"]) for _ in range(n)],
            " Flow Bytes": [r.randint(0, 3) for _ in range(n)],
            " Fwd Pkts": [r.randint(0, 2) for _ in range(n)],
        }
    )
    return _write(df, tmp_path / "cic.csv")


def test_streaming_detecta_etiqueta_y_split_por_nombre(tmp_path):
    """Sin `--label-col`/`--split-col`, el modo normal los detecta y el streaming
    no: `dup.exact` salia sin etiqueta y `dup.cross_split` no corria ni figuraba
    como saltado (AUDITORIA-1.0.md, COR-02)."""
    report = run_streaming_audit(_csv_estilo_cicflowmeter(tmp_path))

    assert any(f.check_id == "dup.cross_split" for f in report.findings)
    assert "dup.cross_split" not in report.skipped


def test_streaming_acepta_el_nombre_sin_el_espacio_de_cicflowmeter(tmp_path):
    """El modo normal hace `strip` de los nombres; `--label-col Label` sobre
    " Label" fallaba con ColumnNotFoundError y salia con codigo 1."""
    report = run_streaming_audit(
        _csv_estilo_cicflowmeter(tmp_path), label_col="Label", split_col="split"
    )
    assert any(f.check_id == "dup.cross_split" for f in report.findings)


def test_streaming_dice_que_dup_cross_split_no_corrio(tmp_path):
    df = pl.DataFrame({"a": [1, 1, 2], "label": ["x", "x", "y"]})
    sin_split = run_streaming_audit(_write(df, tmp_path / "a.csv"), label_col="label")
    assert "split" in sin_split.skipped["dup.cross_split"]

    un_solo = df.with_columns(pl.lit("train").alias("split"))
    un_valor = run_streaming_audit(
        _write(un_solo, tmp_path / "b.csv"), label_col="label", split_col="split"
    )
    assert "un solo valor" in un_valor.skipped["dup.cross_split"]


def test_streaming_y_modo_normal_dan_lo_mismo_sobre_un_csv_de_cicflowmeter(tmp_path):
    """Equivalencia (check_id, filas afectadas) de los cuatro checks compartidos,
    leyendo el mismo CSV por los dos caminos y sin indicar columnas."""
    import vigia

    p = _csv_estilo_cicflowmeter(tmp_path)
    compartidos = set(STREAMING_CHECKS)

    def resumen(report):
        return sorted(
            (f.check_id, f.affected_rows) for f in report.findings if f.check_id in compartidos
        )

    normal = vigia.audit(vigia.load(p), checks="dup.exact,dup.cross_split,validity")
    continuo = run_streaming_audit(p)
    assert resumen(continuo) == resumen(normal)
    assert resumen(normal), "el dataset tiene que producir hallazgos para que la prueba valga"


def test_streaming_aplica_el_perfil_a_un_csv_sin_cabecera(tmp_path):
    """UGR'16 se publica sin cabecera: el perfil aporta los nombres y la etiqueta."""
    fila = "2016-07-27 13:43:21,48.380,1.1.1.1,2.2.2.2,53,53,UDP,.A....,0,0,2,209,background"
    path = tmp_path / "ugr.csv"
    path.write_text("\n".join([fila, fila, "x" + fila[1:]]) + "\n", encoding="utf-8")

    report = run_streaming_audit(path, profile="ugr-16")

    assert report.n_cols == 13
    assert report.n_rows == 3  # ninguna fila se toma como cabecera
    assert any(f.check_id == "dup.exact" for f in report.findings)


def test_streaming_abre_binetflow_de_ctu_13(tmp_path):
    path = tmp_path / "capture.binetflow"
    path.write_text("SrcAddr,Label\n1.1.1.1,flow=Background\n1.1.1.1,flow=Background\n")

    report = run_streaming_audit(path, profile="ctu-13")

    assert report.n_rows == 2


def test_streaming_no_convierte_decimales_tardios_en_nulos(tmp_path):
    filas = ["a,b"] + [f"{i},1" for i in range(12_000)] + ["150.5,1"]
    path = tmp_path / "datos.csv"
    path.write_text("\n".join(filas) + "\n", encoding="utf-8")

    report = run_streaming_audit(path)

    assert not [f for f in report.findings if f.check_id == "validity.nan_inf"]


def test_streaming_agrupa_la_etiqueta_con_el_perfil(tmp_path):
    """Con las etiquetas agrupadas, dos flujos que solo difieren en el subtipo
    de 'background' son duplicados exactos."""
    path = tmp_path / "capture.binetflow"
    path.write_text(
        "SrcAddr,Dport,Label\n"
        "1.1.1.1,80,flow=Background-TCP-Established\n"
        "1.1.1.1,80,flow=Background-UDP-Attempt\n"
        "2.2.2.2,80,flow=From-Normal-V46-Grill\n",
        encoding="utf-8",
    )

    report = run_streaming_audit(path, profile="ctu-13")

    assert any(f.check_id == "dup.exact" for f in report.findings)


def test_streaming_y_modo_normal_coinciden_con_los_roles_declarados(tmp_path):
    """El mismo flujo en otra IP es duplicado en ambos modos si la IP es un rol declarado."""
    import vigia

    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            "bytes": [100, 100, 300],
            "label": ["x", "x", "y"],
        }
    )
    p = _write(df, tmp_path / "r.csv")

    sin_rol = run_streaming_audit(p, label_col="label")
    assert [f for f in sin_rol.findings if f.check_id == "dup.exact"] == []

    stream = run_streaming_audit(p, label_col="label", src_ip_col="src_ip")
    eager = vigia.audit(vigia.load(p, label_col="label", src_ip_col="src_ip"), checks="dup.exact")
    s = [f for f in stream.findings if f.check_id == "dup.exact"]
    e = [f for f in eager.findings if f.check_id == "dup.exact"]
    assert [f.affected_rows for f in s] == [f.affected_rows for f in e] == [1]
