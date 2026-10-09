"""Correcciones automáticas (sección 8.7)."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.fixes import apply_fix, available_fixes
from vigia.fixes.base import FixNotApplicable


def test_todas_las_correcciones_nombradas_existen():
    """Cada `auto_fix` de un hallazgo tiene que poder aplicarse.

    Sin esto, el reporte promete una corrección que no existe.
    """
    disponibles = set(available_fixes())
    # Los ids que los checks nombran en `auto_fix`, según la sección 8.7.
    nombradas = {
        "drop_duplicates",
        "drop_identifiers",
        "drop_constant",
        "strip_column_names",
        "normalize_labels",
        "temporal_split",
        "group_split",
        "quarantine_noise",
    }
    assert nombradas <= disponibles, nombradas - disponibles


def test_drop_duplicates_conserva_la_primera(make_ctx):
    df = pl.DataFrame({"a": [1, 1, 2], "b": [10, 10, 20], "label": ["x", "x", "y"]})
    r = apply_fix(make_ctx(df), "drop_duplicates")
    assert r.rows_before == 3
    assert r.rows_after == 2
    assert r.rows_removed == 1


def test_drop_duplicates_no_toca_conflictos_de_etiqueta(make_ctx):
    """Mismas características y distinta etiqueta no es un duplicado.

    Borrar una de las dos elegiría una etiqueta sin fundamento.
    """
    df = pl.DataFrame({"a": [1, 1], "label": ["BENIGN", "DDoS"]})
    r = apply_fix(make_ctx(df), "drop_duplicates")
    assert r.rows_after == 2


def test_drop_identifiers_quita_ip_y_conserva_la_etiqueta(make_ctx):
    df = pl.DataFrame(
        {
            "Source IP": ["10.0.0.1", "10.0.0.2"],
            "Flow ID": ["a", "b"],
            "bytes_fwd": [1, 2],
            "label": ["x", "y"],
            "split": ["train", "test"],
        }
    )
    r = apply_fix(make_ctx(df, split_col="split"), "drop_identifiers")
    assert set(r.df.columns) == {"bytes_fwd", "label", "split"}
    assert r.cols_removed == 2


def test_drop_constant_elimina_columnas_de_un_valor(make_ctx):
    df = pl.DataFrame({"a": [1, 2], "siempre": [7, 7], "label": ["x", "y"]})
    r = apply_fix(make_ctx(df), "drop_constant")
    assert "siempre" not in r.df.columns
    assert r.cols_removed == 1


def test_strip_column_names(make_ctx):
    df = pl.DataFrame({" Destination Port": [80, 443], "label": ["a", "b"]})
    r = apply_fix(make_ctx(df), "strip_column_names")
    assert "Destination Port" in r.df.columns


def test_normalize_labels_unifica_variantes(make_ctx):
    df = pl.DataFrame(
        {
            "a": list(range(6)),
            "label": ["DoS Hulk", "DoS Hulk", "DoS-Hulk", "dos hulk", "BENIGN", "BENIGN"],
        }
    )
    r = apply_fix(make_ctx(df), "normalize_labels")
    # Gana la variante más frecuente.
    assert set(r.df.get_column("label").to_list()) == {"DoS Hulk", "BENIGN"}


def test_normalize_labels_no_aplica_si_ya_es_consistente(make_ctx):
    df = pl.DataFrame({"a": [1, 2], "label": ["DoS", "BENIGN"]})
    with pytest.raises(FixNotApplicable):
        apply_fix(make_ctx(df), "normalize_labels")


def test_temporal_split_pone_el_pasado_en_entrenamiento(make_ctx):
    df = pl.DataFrame(
        {
            "a": list(range(10)),
            "label": ["x", "y"] * 5,
            "ts": [f"2026-01-{i + 1:02d} 00:00:00" for i in range(10)],
        }
    )
    r = apply_fix(make_ctx(df, time_col="ts"), "temporal_split")
    filas = r.df.sort("a").get_column("split").to_list()
    # Todo el entrenamiento antes que toda la prueba.
    assert filas == sorted(filas, key=lambda s: 0 if s == "train" else 1)
    assert "train" in filas and "test" in filas


def test_temporal_split_elimina_la_fuga(make_ctx):
    """Después de corregir, `leak.temporal` no debe encontrar nada."""
    from vigia.checks.leakage import TemporalLeakCheck

    df = pl.DataFrame(
        {
            "a": list(range(10)),
            "label": ["x", "y"] * 5,
            "split": ["test", "train"] * 5,  # partición mezclada: fuga segura
            "ts": [f"2026-01-{i + 1:02d} 00:00:00" for i in range(10)],
        }
    )
    ctx = make_ctx(df, split_col="split", time_col="ts")
    assert TemporalLeakCheck().run(ctx)  # hay fuga antes

    corregido = apply_fix(ctx, "temporal_split")
    ctx2 = make_ctx(corregido.df, split_col="split", time_col="ts")
    assert TemporalLeakCheck().run(ctx2) == []  # y no después


def test_group_split_mantiene_los_grupos_enteros(make_ctx):
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1"] * 4 + ["10.0.0.2"] * 4,
            "dst_ip": ["8.8.8.8"] * 8,
            "label": ["x", "y"] * 4,
            "a": list(range(8)),
        }
    )
    r = apply_fix(make_ctx(df, src_ip_col="src_ip", dst_ip_col="dst_ip"), "group_split")
    # Cada host cae entero de un lado.
    por_host = r.df.group_by("src_ip").agg(pl.col("split").n_unique().alias("n"))
    assert por_host.get_column("n").max() == 1


def test_group_split_por_host_elimina_la_fuga_por_host(make_ctx):
    from vigia.checks.leakage import HostLeakCheck

    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2"],
            "label": ["attack"] * 4,
            "split": ["train", "test", "train", "test"],  # mismo host a ambos lados
        }
    )
    ctx = make_ctx(df, split_col="split", src_ip_col="src_ip")
    assert HostLeakCheck().run(ctx)

    corregido = apply_fix(
        make_ctx(df, split_col="split", src_ip_col="src_ip", config={"group_by": "host"}),
        "group_split",
    )
    ctx2 = make_ctx(corregido.df, split_col="split", src_ip_col="src_ip")
    assert HostLeakCheck().run(ctx2) == []


def test_group_split_avisa_de_los_hosts_que_no_puede_separar(make_ctx):
    """Un servidor que habla con todos no puede estar de un solo lado.

    Agrupar por la 5-tupla separa las conexiones pero deja ese host a ambos
    lados. El resultado tiene que decirlo, no dejar creer que `leak.host`
    quedó resuelto.
    """
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2"],
            "dst_ip": ["8.8.8.8"] * 4,  # el mismo servidor en todas las conexiones
            "label": ["attack"] * 4,
        }
    )
    r = apply_fix(make_ctx(df, src_ip_col="src_ip", dst_ip_col="dst_ip"), "group_split")
    assert r.details["hosts_aun_compartidos"]
    assert "ambos lados" in r.summary


def test_group_split_se_niega_sin_columnas_de_grupo(make_ctx):
    df = pl.DataFrame({"a": [1, 2], "label": ["x", "y"]})
    with pytest.raises(FixNotApplicable, match="IP"):
        apply_fix(make_ctx(df), "group_split")


def test_quarantine_noise_aparta_sin_borrar(make_ctx):
    """Ninguna fila se pierde: las dudosas quedan para revisión humana."""
    pytest.importorskip("cleanlab")

    labels, f1, f2 = [], [], []
    for i in range(300):
        es_ataque = i % 2 == 0
        labels.append("attack" if es_ataque else "benign")
        base = 100.0 if es_ataque else 10.0
        f1.append(base + (i % 7) * 0.4)
        f2.append(base * 2 + (i % 5) * 0.3)
    for i in range(15):  # ruido sembrado
        labels[i] = "benign" if labels[i] == "attack" else "attack"

    df = pl.DataFrame({"bytes_fwd": f1, "bytes_bwd": f2, "label": labels})
    r = apply_fix(make_ctx(df), "quarantine_noise")

    assert r.quarantined is not None
    assert r.quarantined.height > 0
    # La suma se conserva: apartar no es borrar.
    assert r.rows_after + r.quarantined.height == r.rows_before


def test_quarantine_noise_no_aplica_sin_ruido(make_ctx):
    pytest.importorskip("cleanlab")

    labels, f1, f2 = [], [], []
    for i in range(200):
        es_ataque = i % 2 == 0
        labels.append("attack" if es_ataque else "benign")
        base = 100.0 if es_ataque else 10.0
        f1.append(base + (i % 7) * 0.4)
        f2.append(base * 2 + (i % 5) * 0.3)

    df = pl.DataFrame({"bytes_fwd": f1, "bytes_bwd": f2, "label": labels})
    with pytest.raises(FixNotApplicable):
        apply_fix(make_ctx(df), "quarantine_noise")


def test_correccion_desconocida(make_ctx):
    df = pl.DataFrame({"a": [1], "label": ["x"]})
    with pytest.raises(KeyError):
        apply_fix(make_ctx(df), "no_existe")


def test_drop_constant_ignora_los_nulos(make_ctx):
    """El mismo criterio que `validity.constant`: lo que el check reporta, la
    corrección lo quita (AUDITORIA-1.0.md, COR-12)."""
    df = pl.DataFrame({"casi": [7, 7, 7, None], "varia": [1, 2, 3, None], "label": list("abab")})
    r = apply_fix(make_ctx(df), "drop_constant")
    assert r.df.columns == ["varia", "label"]


def test_temporal_split_no_manda_a_prueba_las_filas_sin_tiempo(make_ctx):
    """Las filas sin tiempo iban a "test" por el `otherwise`: una fila sin
    fecha no puede estar ni antes ni despues del corte (AUDITORIA-1.0.md, SCI-09)."""
    df = pl.DataFrame(
        {
            "x": list(range(6)),
            "ts": [
                "2026-01-01 00:00:00",
                "2026-01-02 00:00:00",
                "2026-01-03 00:00:00",
                "2026-01-04 00:00:00",
                None,
                None,
            ],
        }
    )
    r = apply_fix(make_ctx(df, time_col="ts"), "temporal_split")
    assert r.df.filter(pl.col("ts").is_null()).get_column("split").null_count() == 2
    assert r.details["n_sin_tiempo"] == 2
    assert "sin tiempo" in r.summary


def test_temporal_split_con_tiempo_ambiguo_no_aplica(make_ctx):
    # 01/02 y 02/01: como d/m, el primero es posterior; como m/d, anterior.
    df = pl.DataFrame({"x": [1, 2, 3], "ts": ["01/02/2017", "02/01/2017", "03/03/2017"]})
    with pytest.raises(FixNotApplicable, match="ambigu"):
        apply_fix(make_ctx(df, time_col="ts"), "temporal_split")


def _duplicados_con_hora_distinta(n: int = 300) -> pl.DataFrame:
    """Flujos que solo difieren en la hora: duplicados si la hora es un rol declarado."""
    return pl.DataFrame(
        {
            "Timestamp": [f"2017-07-03 10:{i % 60:02d}:{(i * 7) % 60:02d}" for i in range(n)],
            "bytes": [i % 5 for i in range(n)],
            "pkts": [i % 3 for i in range(n)],
            "Label": ["BENIGN" if i % 2 else "DoS" for i in range(n)],
        }
    )


@pytest.mark.parametrize("declarar_hora", [True, False])
def test_fix_drop_duplicates_y_reauditar_no_deja_dup_exact(tmp_path, declarar_hora):
    """Propiedad: lo que `dup.exact` reporta, `vigia fix --apply drop_duplicates`
    lo quita, con columnas de rol declaradas o sin ellas.

    La cadena de `vigia fix` reconstruia el contexto sin `declared_roles`, asi
    que la hora declarada volvia a entrar en la clave de deduplicacion y la
    re-auditoria seguia dando 89 % de duplicados (AUDITORIA-1.0.md, COR-01).
    """
    from typer.testing import CliRunner

    import vigia
    from vigia.cli import app

    src = tmp_path / "flows.csv"
    out = tmp_path / "flows_fix.csv"
    _duplicados_con_hora_distinta().write_csv(src)
    opts = ["--time-col", "Timestamp"] if declarar_hora else []

    r = CliRunner().invoke(
        app, ["fix", str(src), "--apply", "drop_duplicates", "--out", str(out), *opts]
    )
    assert r.exit_code == 0, r.output

    kwargs = {"time_col": "Timestamp"} if declarar_hora else {}
    reporte = vigia.audit(vigia.load(out, **kwargs), checks="dup.exact")
    assert [f.check_id for f in reporte.findings] == []


def test_fix_acepta_perfil(tmp_path):
    """Un perfil declara roles (tiempo, IPs) que cambian la clave de
    deduplicacion: sin `--profile`, `vigia fix` no podia corregir con los
    mismos roles con los que `vigia audit --profile` habia auditado."""
    from typer.testing import CliRunner

    from vigia.cli import app

    src = tmp_path / "flows.csv"
    _duplicados_con_hora_distinta().write_csv(src)
    out = tmp_path / "out.csv"
    runner = CliRunner()

    ok = runner.invoke(
        app,
        ["fix", str(src), "--apply", "drop_duplicates", "--out", str(out),
         "--profile", "cic-ids-2017"],
    )  # fmt: skip
    assert ok.exit_code == 0, ok.output

    malo = runner.invoke(
        app,
        ["fix", str(src), "--apply", "drop_duplicates", "--out", str(out),
         "--profile", "no-existe"],
    )  # fmt: skip
    assert malo.exit_code == 2
    assert "perfil" in malo.output


def test_with_df_conserva_los_roles_y_no_arrastra_las_caches(make_ctx):
    from vigia.core.context import AuditContext

    df = _duplicados_con_hora_distinta(10)
    ctx = AuditContext(df=df, label_col="Label", declared_roles=frozenset({"Timestamp"}))
    _ = ctx.row_hash, ctx.shared  # llena las caches del original
    ctx.shared["algo"] = 1

    nuevo = ctx.with_df(df.head(4))
    assert nuevo.declared_roles == frozenset({"Timestamp"})
    assert nuevo.label_col == "Label"
    assert nuevo.row_hash.len() == 4
    assert "algo" not in nuevo.shared


def test_el_resultado_registra_lo_que_hizo(make_ctx):
    df = pl.DataFrame({"a": [1, 1, 2], "label": ["x", "x", "y"]})
    r = apply_fix(make_ctx(df), "drop_duplicates")
    d = r.to_dict()
    assert d["fix_id"] == "drop_duplicates"
    assert d["rows_removed"] == 1
    assert "duplicadas" in d["summary"]
