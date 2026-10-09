"""Checks de atajos."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.checks.shortcuts import IdentifierColumnCheck, SingleFeatureShortcutCheck
from vigia.core.context import CheckSkipped


def test_atajo_por_columna_delatora(make_ctx):
    n = 60
    df = pl.DataFrame(
        {
            "ruido": [i % 5 for i in range(n)],
            # 'delator' coincide exactamente con la etiqueta: atajo perfecto.
            "delator": [0 if i < 30 else 1 for i in range(n)],
            "label": ["benign" if i < 30 else "attack" for i in range(n)],
        }
    )
    findings = SingleFeatureShortcutCheck().run(make_ctx(df))
    ids = {f.title.split("'")[1] for f in findings}
    assert "delator" in ids
    assert "ruido" not in ids
    delator = next(f for f in findings if "'delator'" in f.title)
    assert delator.metric["balanced_accuracy"] == pytest.approx(1.0)
    assert delator.severity == "critical"


def test_columna_unica_por_fila_no_se_reporta_como_atajo(make_ctx):
    """Cardinalidad ~= n filas: acertar es memorizar, no es evidencia de atajo.

    Si no se filtrara, cualquier columna continua (una duración float, por
    ejemplo) daría exactitud 1.0 y el reporte se llenaría de falsos positivos.
    """
    n = 40
    df = pl.DataFrame(
        {
            "flow_id": [f"f{i}" for i in range(n)],  # única por fila
            "label": ["benign" if i % 2 else "attack" for i in range(n)],
        }
    )
    assert SingleFeatureShortcutCheck().run(make_ctx(df)) == []


def test_columna_continua_no_genera_falso_positivo(make_ctx):
    n = 50
    df = pl.DataFrame(
        {
            "duration": [round(i * 0.37, 2) for i in range(n)],  # todos distintos
            "label": ["attack" if (i * 13) % 7 < 3 else "benign" for i in range(n)],
        }
    )
    assert SingleFeatureShortcutCheck().run(make_ctx(df)) == []


def test_columna_continua_que_separa_por_umbral_se_reporta(make_ctx):
    """El atajo típico de un árbol: `x > 0.5` predice la etiqueta. Se descartaba
    por tener un valor distinto por fila y no lo reportaba nadie
    (AUDITORIA-1.0.md, SCI-05)."""
    import random

    r = random.Random(0)
    xs = [r.random() for _ in range(5000)]
    df = pl.DataFrame(
        {"flow_iat_min": xs, "label": ["attack" if x > 0.5 else "benign" for x in xs]}
    )
    findings = SingleFeatureShortcutCheck().run(make_ctx(df))
    assert [f.title for f in findings if "flow_iat_min" in f.title], findings
    assert findings[0].metric["n_tramos"] > 0


def test_ruido_continuo_puro_no_se_reporta(make_ctx):
    """Control de falsos positivos de la discretización: una columna continua
    independiente de la etiqueta no puede pasar el umbral."""
    import random

    r = random.Random(1)
    n = 5000
    df = pl.DataFrame(
        {
            "ruido_a": [r.random() for _ in range(n)],
            "ruido_b": [r.gauss(0, 1) for _ in range(n)],
            "label": [r.choice(["attack", "benign", "dos"]) for _ in range(n)],
        }
    )
    assert SingleFeatureShortcutCheck().run(make_ctx(df)) == []


def test_se_salta_con_una_sola_clase(make_ctx):
    df = pl.DataFrame({"a": [1, 2, 3], "label": ["x", "x", "x"]})
    with pytest.raises(CheckSkipped):
        SingleFeatureShortcutCheck().run(make_ctx(df))


def test_identificador_se_reporta_por_nombre(make_ctx):
    """El caso de alta cardinalidad lo cubre `shortcut.identifier`."""
    df = pl.DataFrame(
        {
            "flow_id": [f"f{i}" for i in range(10)],
            "duration": [1.0] * 10,
            "label": ["a", "b"] * 5,
        }
    )
    findings = IdentifierColumnCheck().run(make_ctx(df))
    assert len(findings) == 1
    assert findings[0].auto_fix == "drop_identifiers"
    assert findings[0].metric["n_identifier_cols"] == 1.0


def test_source_ip_se_reconoce_como_identificador(make_ctx):
    df = pl.DataFrame({"Source IP": ["10.0.0.1"] * 4, "label": ["a", "b"] * 2})
    assert len(IdentifierColumnCheck().run(make_ctx(df))) == 1


@pytest.mark.parametrize("nombre", ["ruido", "fluid_ratio", "guide", "flow_idle_time"])
def test_palabras_que_solo_contienen_uid_o_flow_id_no_son_identificadores(nombre):
    """`uid` y `flow.?id` sin borde marcaban "ruido" o "flow_idle_time", que
    entonces salían de los modelos auxiliares y `drop_identifiers` las borraba
    (AUDITORIA-1.0.md, COR-13)."""
    from vigia.checks.shortcuts import _looks_like_identifier

    assert not _looks_like_identifier(nombre)


@pytest.mark.parametrize("nombre", ["uid", "UID", "Flow ID", "flow_id", "FlowID", "conn_uid"])
def test_los_identificadores_reales_se_siguen_reconociendo(nombre):
    from vigia.checks.shortcuts import _looks_like_identifier

    assert _looks_like_identifier(nombre)


def test_columnas_normales_no_son_identificadores(make_ctx):
    df = pl.DataFrame({"bytes_fwd": [1, 2], "duration": [0.5, 1.5], "label": ["a", "b"]})
    assert IdentifierColumnCheck().run(make_ctx(df)) == []


def test_identifier_ignora_las_columnas_de_rol_declaradas(make_ctx):
    df = pl.DataFrame(
        {
            "src_ip": ["10.0.0.1"] * 4,
            "flow_id": ["a", "b", "c", "d"],
            "bytes": [1, 2, 3, 4],
            "label": ["x", "y", "x", "y"],
        }
    )
    declaradas = make_ctx(df, declared_roles=frozenset({"src_ip"}))
    findings = IdentifierColumnCheck().run(declaradas)
    # `flow_id` nadie la declaró como metadato: se sigue marcando.
    assert [e["columna"] for e in findings[0].examples] == ["flow_id"]

    # Detectada por nombre pero sin declarar: se marca como siempre.
    sin_declarar = IdentifierColumnCheck().run(make_ctx(df))
    assert {e["columna"] for e in sin_declarar[0].examples} == {"src_ip", "flow_id"}


def test_identifier_calla_si_solo_quedan_columnas_declaradas(make_ctx):
    df = pl.DataFrame({"src_ip": ["a", "b"], "bytes": [1, 2], "label": ["x", "y"]})
    ctx = make_ctx(df, declared_roles=frozenset({"src_ip"}))
    assert IdentifierColumnCheck().run(ctx) == []
