"""Checks de fuga entre entrenamiento y prueba."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.checks.leakage import HostLeakCheck, SessionLeakCheck, TemporalLeakCheck
from vigia.core.context import CheckSkipped


def test_fuga_temporal_prueba_anterior_a_entrenamiento(make_ctx):
    df = pl.DataFrame(
        {
            "x": list(range(6)),
            "label": ["a", "b"] * 3,
            "split": ["test"] * 3 + ["train"] * 3,
            "ts": [
                "2026-01-01 00:00:00",
                "2026-01-01 01:00:00",
                "2026-01-01 02:00:00",
                "2026-02-01 00:00:00",
                "2026-02-01 01:00:00",
                "2026-02-01 02:00:00",
            ],
        }
    )
    findings = TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].metric["overlap_ratio"] == pytest.approx(1.0)


def test_split_temporal_correcto_no_reporta(make_ctx):
    df = pl.DataFrame(
        {
            "x": list(range(4)),
            "label": ["a", "b", "a", "b"],
            "split": ["train", "train", "test", "test"],
            "ts": [
                "2026-01-01 00:00:00",
                "2026-01-01 01:00:00",
                "2026-03-01 00:00:00",
                "2026-03-01 01:00:00",
            ],
        }
    )
    assert TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts")) == []


def test_fuga_temporal_con_instantes_simultaneos(make_ctx):
    """Filas de prueba en el mismo instante que el fin del entrenamiento.

    CIC-IDS2017 marca el tiempo al segundo y miles de flujos comparten
    instante, así que comparar con `<` estricto dejaba pasar solape real.
    """
    df = pl.DataFrame(
        {
            "x": list(range(8)),
            "label": ["a", "b"] * 4,
            "split": ["train"] * 4 + ["test"] * 4,
            "ts": [
                "2026-07-01 00:00:00",
                "2026-07-02 00:00:00",
                "2026-07-03 00:00:00",
                "2026-07-03 00:00:00",  # fin del entrenamiento
                "2026-07-03 00:00:00",  # simultáneas: son solape
                "2026-07-03 00:00:00",
                "2026-07-04 00:00:00",
                "2026-07-05 00:00:00",
            ],
        }
    )
    findings = TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))
    assert len(findings) == 1
    assert findings[0].metric["n_test_rows_before_train_end"] == 2.0
    assert findings[0].metric["overlap_ratio"] == pytest.approx(0.5)


def test_prueba_contenida_en_entrenamiento_se_nombra_asi(make_ctx):
    """El split aleatorio deja la prueba dentro del periodo de entrenamiento."""
    df = pl.DataFrame(
        {
            "x": list(range(6)),
            "label": ["a", "b"] * 3,
            "split": ["train", "train", "train", "test", "test", "test"],
            "ts": [
                "2026-01-01 00:00:00",
                "2026-06-01 00:00:00",
                "2026-12-01 00:00:00",
                "2026-03-01 00:00:00",
                "2026-04-01 00:00:00",
                "2026-05-01 00:00:00",
            ],
        }
    )
    findings = TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "contenido" in findings[0].description


def _split_por_tiempo(train: list[str], test: list[str]) -> pl.DataFrame:
    return pl.DataFrame(
        {
            "x": list(range(len(train) + len(test))),
            "split": ["train"] * len(train) + ["test"] * len(test),
            "ts": train + test,
        }
    )


def test_fechas_us_con_dias_mayores_a_12_se_interpretan_bien(make_ctx):
    """Caso 1 de SCI-02: julio contra agosto en m/d/Y. Antes el formato d/m
    interpretaba solo el test y el check se saltaba con un motivo falso."""
    df = _split_por_tiempo(
        [f"07/{d:02d}/2017 10:00:00" for d in range(25, 32)] * 5,
        [f"08/{d:02d}/2017 10:00:00" for d in range(1, 6)] * 5,
    )
    assert TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts")) == []


def test_fechas_ambiguas_d_m_contra_m_d_se_saltan_y_piden_el_formato(make_ctx):
    """Caso 2 de SCI-02: con dias <= 12, d/m y m/d interpretan todo y dan
    ordenes distintos. Antes se elegia d/m y salia un critico falso del 100 %."""
    df = _split_por_tiempo(
        [f"07/{d:02d}/2017 10:00:00" for d in range(1, 11)] * 5,
        [f"08/{d:02d}/2017 10:00:00" for d in range(1, 6)] * 5,
    )
    with pytest.raises(CheckSkipped, match="ambigu"):
        TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))

    ctx = make_ctx(
        df, split_col="split", time_col="ts", config={"time_format": "%m/%d/%Y %H:%M:%S"}
    )
    assert TemporalLeakCheck().run(ctx) == []


def _csv_fechas_ambiguas(tmp_path):
    p = tmp_path / "ambiguo.csv"
    _split_por_tiempo(
        [f"07/{d:02d}/2017 10:00:00" for d in range(1, 11)] * 5,
        [f"08/{d:02d}/2017 10:00:00" for d in range(1, 6)] * 5,
    ).write_csv(p)
    return p


def test_cli_audit_acepta_time_format(tmp_path):
    """El skip por ambiguedad pide `--time-format`: la opcion tiene que existir."""
    from typer.testing import CliRunner

    from vigia.cli import app

    p = _csv_fechas_ambiguas(tmp_path)
    out = tmp_path / "rep"
    args = ["audit", str(p), "--split-col", "split", "--time-col", "ts", "--checks",
            "leak.temporal", "--report", str(out)]  # fmt: skip
    sin = CliRunner().invoke(app, args)
    assert sin.exit_code == 0, sin.output
    assert "ambigu" in (out / "report.json").read_text(encoding="utf-8")

    con = CliRunner().invoke(app, [*args, "--time-format", "%m/%d/%Y %H:%M:%S"])
    assert con.exit_code == 0, con.output
    assert '"leak.temporal"' not in (out / "report.json").read_text(encoding="utf-8")


def test_el_perfil_puede_fijar_time_format(tmp_path, monkeypatch):
    import vigia

    p = _csv_fechas_ambiguas(tmp_path)
    monkeypatch.setattr(
        "vigia.load_profile",
        lambda _id: {"column_roles": {"time_col": "ts"}, "time_format": "%m/%d/%Y %H:%M:%S"},
    )
    ctx = vigia.load(p, split_col="split", profile="falso")
    assert ctx.option("time_format", None) == "%m/%d/%Y %H:%M:%S"
    # Un formato explicito gana sobre el del perfil, como las columnas.
    ctx = vigia.load(p, split_col="split", profile="falso", time_format="%d/%m/%Y %H:%M:%S")
    assert ctx.option("time_format", None) == "%d/%m/%Y %H:%M:%S"


def test_filas_con_otro_formato_no_se_descartan_en_silencio(make_ctx):
    """Caso 4 de SCI-01: el 10 % del test es anterior al entrenamiento pero
    esta escrito en otro formato. Antes se descartaba y el check no decia nada."""
    df = _split_por_tiempo(
        [f"2017-07-{d:02d} 10:00:00" for d in range(10, 20)] * 50,
        [f"2017-07-{d:02d} 11:00:00" for d in range(21, 30)] * 45
        + [f"{d}/7/2017 9:00" for d in range(1, 9)] * 5,
    )
    with pytest.raises(CheckSkipped, match="40 de 945"):
        TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))


def test_split_sin_tiempo_no_se_confunde_con_split_no_reconocido(make_ctx):
    df = pl.DataFrame(
        {
            "x": [1, 2, 3, 4],
            "split": ["train", "train", "test", "test"],
            "ts": ["2026-01-01 00:00:00", "2026-01-02 00:00:00", None, None],
        }
    )
    with pytest.raises(CheckSkipped, match="tiempo") as exc:
        TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))
    assert "no se reconocen" not in str(exc.value)


def test_se_salta_sin_splits_reconocibles(make_ctx):
    df = pl.DataFrame(
        {
            "label": ["a", "b"],
            "split": ["fold1", "fold2"],
            "ts": ["2026-01-01 00:00:00", "2026-01-02 00:00:00"],
        }
    )
    with pytest.raises(CheckSkipped):
        TemporalLeakCheck().run(make_ctx(df, split_col="split", time_col="ts"))


def test_validacion_cuenta_como_entrenamiento(make_ctx):
    """Un host compartido entre 'val' y 'test' también es fuga.

    La validación es parte de lo que el modelo ve al ajustarse.
    """
    df = pl.DataFrame(
        {
            "x": list(range(4)),
            "label": ["attack"] * 4,
            "split": ["val", "val", "test", "test"],
            "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.9"],
        }
    )
    findings = HostLeakCheck().run(make_ctx(df, split_col="split", src_ip_col="src_ip"))
    assert len(findings) == 1
    assert findings[0].metric["n_shared_hosts"] == 1.0


def test_splits_no_reconocidos_se_declaran(make_ctx):
    """Las filas que quedan fuera del análisis deben nombrarse en el hallazgo."""
    df = pl.DataFrame(
        {
            "x": list(range(5)),
            "label": ["attack"] * 5,
            "split": ["train", "test", "test", "calibracion", "calibracion"],
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        }
    )
    findings = HostLeakCheck().run(make_ctx(df, split_col="split", src_ip_col="src_ip"))
    assert len(findings) == 1
    assert "calibracion" in findings[0].description


def test_fuga_por_host(make_ctx):
    df = pl.DataFrame(
        {
            "x": list(range(6)),
            "label": ["attack"] * 6,
            "split": ["train", "train", "train", "test", "test", "test"],
            "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.1", "10.0.0.1", "10.0.0.9"],
        }
    )
    findings = HostLeakCheck().run(make_ctx(df, split_col="split", src_ip_col="src_ip"))
    assert len(findings) == 1
    assert findings[0].metric["n_shared_hosts"] == 1.0
    assert findings[0].affected_rows == 2
    assert findings[0].severity == "critical"  # 2 de 3 filas de prueba


def test_hosts_disjuntos_no_reportan(make_ctx):
    df = pl.DataFrame(
        {
            "x": list(range(4)),
            "label": ["attack"] * 4,
            "split": ["train", "train", "test", "test"],
            "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.8", "10.0.0.9"],
        }
    )
    assert HostLeakCheck().run(make_ctx(df, split_col="split", src_ip_col="src_ip")) == []


def test_se_salta_sin_columna_de_ip(make_ctx):
    df = pl.DataFrame({"label": ["a", "b"], "split": ["train", "test"]})
    with pytest.raises(CheckSkipped):
        HostLeakCheck().run(make_ctx(df, split_col="split"))


def test_fuga_por_sesion(make_ctx):
    """La misma 5-tupla partida en varios flujos a ambos lados del split."""
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.9"],
            "dst_ip": ["8.8.8.8", "8.8.8.8", "8.8.4.4", "1.1.1.1"],
            "src_port": [5000, 5000, 6000, 7000],
            "dst_port": [443, 443, 443, 80],
            "proto": [6, 6, 6, 6],
            "label": ["a", "a", "b", "b"],
            "split": ["train", "test", "train", "test"],
        }
    )
    findings = SessionLeakCheck().run(
        make_ctx(
            df,
            split_col="split",
            src_ip_col="src_ip",
            dst_ip_col="dst_ip",
            src_port_col="src_port",
            dst_port_col="dst_port",
            protocol_col="proto",
        )
    )
    assert len(findings) == 1
    assert findings[0].metric["n_sesiones_compartidas"] == 1.0
    assert findings[0].auto_fix == "group_split"


def test_sesiones_disjuntas_no_reportan(make_ctx):
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.1"],
            "dst_ip": ["8.8.8.8", "8.8.8.8"],
            "src_port": [5000, 5001],  # puerto distinto: otra conexión
            "dst_port": [443, 443],
            "proto": [6, 6],
            "label": ["a", "b"],
            "split": ["train", "test"],
        }
    )
    assert (
        SessionLeakCheck().run(
            make_ctx(
                df,
                split_col="split",
                src_ip_col="src_ip",
                dst_ip_col="dst_ip",
                src_port_col="src_port",
                dst_port_col="dst_port",
                protocol_col="proto",
            )
        )
        == []
    )


def test_sesion_se_salta_sin_la_cinco_tupla(make_ctx):
    """Sin puertos solo quedaría un par de hosts, que ya mira `leak.host`."""
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.1"],
            "dst_ip": ["8.8.8.8", "8.8.8.8"],
            "label": ["a", "b"],
            "split": ["train", "test"],
        }
    )
    with pytest.raises(CheckSkipped, match="5-tupla"):
        SessionLeakCheck().run(
            make_ctx(df, split_col="split", src_ip_col="src_ip", dst_ip_col="dst_ip")
        )


def test_sesion_se_salta_con_cuatro_de_cinco_columnas(make_ctx):
    """Sin el puerto de origen dos "sesiones" son pares host-servicio, no
    conexiones: el check daba crítico por algo que ya mira `leak.host`. La doc
    dice que se salta si falta alguna (AUDITORIA-1.0.md, COR-04)."""
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1"] * 4,
            "dst_ip": ["8.8.8.8"] * 4,
            "dst_port": [53] * 4,
            "protocol": [17] * 4,
            "label": ["a", "b", "a", "b"],
            "split": ["train", "test", "train", "test"],
        }
    )
    ctx = make_ctx(
        df,
        split_col="split",
        src_ip_col="src_ip",
        dst_ip_col="dst_ip",
        dst_port_col="dst_port",
        protocol_col="protocol",
    )
    with pytest.raises(CheckSkipped, match="5-tupla"):
        SessionLeakCheck().run(ctx)


def test_sport_se_detecta_como_puerto_de_origen():
    """CTU-13 llama `Sport` a la columna; sin el candidato `sport` la 5-tupla
    nunca estaba completa en ese dataset."""
    from vigia.io.readers import detect_column

    assert detect_column(pl.DataFrame({"Sport": [1], "Dport": [2]}), "src_port") == "Sport"
    # No se confunde con `dsport` (UNSW-NB15: puerto de destino) ni con una
    # columna que solo lo contiene.
    assert detect_column(pl.DataFrame({"dsport": [1], "pkts_sport": [2]}), "src_port") is None


def test_el_perfil_ctu13_declara_el_puerto_de_origen():
    from vigia.profiles import load_profile

    assert load_profile("ctu-13")["column_roles"]["src_port_col"] == "Sport"
