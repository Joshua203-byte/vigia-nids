"""Módulo 2: simulador, detectores y puntaje combinado."""

from __future__ import annotations

import random

import polars as pl
import pytest

from vigia.core.context import AuditContext
from vigia.core.engine import run_audit
from vigia.core.findings import Finding
from vigia.poison import (
    combine_scores,
    inject_backdoor,
    inject_label_flip,
    inject_synthetic,
    rank_suspects,
)

pytest.importorskip("sklearn")


def _limpio(n: int = 1500, seed: int = 0) -> pl.DataFrame:
    """Dos clases bien separadas y sin nada envenenado."""
    r = random.Random(seed)
    filas = []
    for i in range(n):
        ataque = i % 3 == 0
        base = 800.0 if ataque else 120.0
        filas.append(
            {
                "bytes_fwd": base + r.gauss(0, 40),
                "bytes_bwd": base * 0.6 + r.gauss(0, 30),
                "duracion": (2.0 if ataque else 8.0) + r.gauss(0, 0.8),
                "pkts": (40 if ataque else 12) + r.randint(-4, 4),
                "win": r.choice([8192, 16384, 65535]),
                "Label": "DDoS" if ataque else "BENIGN",
            }
        )
    return pl.DataFrame(filas)


def _ctx(df: pl.DataFrame) -> AuditContext:
    return AuditContext(df=df, path="sim", sha256="0" * 64, label_col="Label", seed=42)


def _corre(df: pl.DataFrame):
    return run_audit(_ctx(df), module="poison")


# --- Simulador ----------------------------------------------------------------


def test_label_flip_cambia_las_etiquetas_que_dice(make_ctx):
    base = _limpio(300)
    spec = inject_label_flip(base, "Label", ratio=0.05, seed=1)
    assert spec.n_poisoned == 15
    antes = base.get_column("Label").to_list()
    despues = spec.df.get_column("Label").to_list()
    cambiadas = [i for i in range(len(antes)) if antes[i] != despues[i]]
    assert cambiadas == spec.poisoned_idx


def test_label_flip_respeta_la_clase_de_origen():
    base = _limpio(300)
    spec = inject_label_flip(base, "Label", ratio=0.05, from_label="DDoS", seed=1)
    originales = base.get_column("Label").to_list()
    assert all(originales[i] == "DDoS" for i in spec.poisoned_idx)


def test_backdoor_inserta_el_trigger_y_la_etiqueta():
    base = _limpio(300)
    spec = inject_backdoor(
        base, "Label", "win", trigger_value=31337, target_label="BENIGN", ratio=0.05, seed=1
    )
    sub = spec.df[spec.poisoned_idx]
    assert set(sub.get_column("win").to_list()) == {31337}
    assert set(sub.get_column("Label").to_list()) == {"BENIGN"}


def test_synthetic_agrega_filas_al_final():
    base = _limpio(300)
    spec = inject_synthetic(base, "Label", n_rows=25, source_label="DDoS", seed=1)
    assert spec.df.height == base.height + 25
    assert spec.poisoned_idx == list(range(base.height, base.height + 25))


def test_evaluate_mide_contra_la_verdad():
    base = _limpio(200)
    spec = inject_label_flip(base, "Label", ratio=0.05, seed=1)
    # Detector perfecto.
    m = spec.evaluate(spec.poisoned_idx)
    assert m["precision"] == 1.0 and m["recall"] == 1.0
    # Detector que no encuentra nada.
    assert spec.evaluate([])["recall"] == 0.0
    # Detector que marca todo: recall perfecto, precisión pésima.
    m = spec.evaluate(list(range(spec.df.height)))
    assert m["recall"] == 1.0
    assert m["precision"] < 0.1


def test_with_flag_marca_las_envenenadas():
    spec = inject_label_flip(_limpio(200), "Label", ratio=0.05, seed=1)
    marcado = spec.with_flag()
    assert int(marcado.get_column("__poisoned").sum()) == spec.n_poisoned


# --- Los detectores encuentran lo que se sembró -------------------------------


def test_knn_detecta_el_cambio_de_etiqueta():
    spec = inject_label_flip(_limpio(), "Label", ratio=0.02, seed=7)
    rep = _corre(spec.df)
    knn = [f for f in rep.findings if f.check_id == "poison.knn"]
    assert knn, rep.skipped
    m = spec.evaluate(knn[0].row_indices)
    assert m["recall"] >= 0.8, m
    assert m["precision"] >= 0.8, m


def test_trigger_detecta_la_puerta_trasera():
    spec = inject_backdoor(
        _limpio(), "Label", "win", trigger_value=31337, target_label="BENIGN", ratio=0.02, seed=7
    )
    rep = _corre(spec.df)
    trig = [f for f in rep.findings if f.check_id == "poison.trigger"]
    assert trig, rep.skipped
    m = spec.evaluate(trig[0].row_indices)
    assert m["recall"] >= 0.9, m
    assert m["precision"] >= 0.9, m


def test_detecta_la_inyeccion_sintetica():
    spec = inject_synthetic(
        _limpio(), "Label", n_rows=60, target_label="BENIGN", source_label="DDoS", seed=7
    )
    rep = _corre(spec.df)
    sus = rank_suspects(rep.findings, top=120, min_detectors=1)
    m = spec.evaluate([s.row for s in sus])
    assert m["recall"] >= 0.8, m


# --- Y se callan cuando no hay nada -------------------------------------------


def test_control_dataset_limpio_no_dispara_coincidencias():
    """El control de falsos positivos del módulo.

    `poison.loss` siempre reporta su 1 % peor por diseño, así que lo que
    importa es que ninguna fila sea señalada por dos detectores distintos.
    """
    rep = _corre(_limpio())
    sus = rank_suspects(rep.findings, min_detectors=2)
    assert len(sus) == 0, [s.detectors for s in sus[:5]]


def test_trigger_no_confunde_una_caracteristica_legitima():
    """`pkts=40` es el tamaño típico del DDoS, no una puerta trasera.

    Regresión: comparando el lift solo contra las otras clases, una
    característica discriminativa daba lift de 258 y el detector marcaba el
    100 % de las filas de un dataset limpio.
    """
    rep = _corre(_limpio())
    trig = [f for f in rep.findings if f.check_id == "poison.trigger"]
    assert not trig, trig[0].examples if trig else None


def test_trigger_no_marca_una_distribucion_de_conteo():
    """Una variable de conteo ancha no es una puerta trasera.

    Regresión encontrada sobre CIC-IDS2017: los límites del detector se
    aplicaban valor por valor, y `Total Fwd Packets` aportaba los valores 13,
    16, 17, 18, 20, 23, 24, 25 y 26. Cada uno pasaba los tres filtros —son
    raros globalmente porque la masa está repartida entre cientos de valores—
    pero juntos son la distribución normal de la columna. Con 884 candidatos
    así, el detector marcaba el 74 % de un dataset limpio.

    Los datos sintéticos no lo mostraban: `_limpio` usa `win` con tres valores
    posibles, y con tan pocos el problema no aparece.
    """
    r = random.Random(11)
    # Hacen falta las tres condiciones juntas para reproducirlo, y por eso el
    # fixture `_limpio` no lo mostraba: volumen suficiente para que cada valor
    # supere MIN_SUPPORT, varias columnas de conteo con cola larga, y clases
    # muy desbalanceadas como las de un dataset de intrusiones real.
    n = 30_000
    filas = []
    for i in range(n):
        ataque = i % 40 == 0  # ~2,5 % de ataque, no 33 %
        fila: dict[str, object] = {
            "bytes_fwd": (800.0 if ataque else 120.0) + r.gauss(0, 40),
            "Label": "DDoS" if ataque else "BENIGN",
        }
        # Las medias difieren por clase, como en el tráfico real: un DDoS tiene
        # otro perfil de paquetes que una sesión normal. Es lo que hace que
        # muchos valores a la vez den lift alto contra la otra clase.
        for nombre, media in (
            ("fwd_packets", 30),
            ("bwd_packets", 25),
            ("fwd_header_len", 40),
            ("bwd_header_len", 35),
            ("min_seg_size", 20),
        ):
            m = media * (2.5 if ataque else 1.0)
            fila[nombre] = max(1, int(r.gauss(m, m * 0.6)))
        filas.append(fila)
    df = pl.DataFrame(filas)

    rep = _corre(df)
    trig = [f for f in rep.findings if f.check_id == "poison.trigger"]
    if trig:
        marcadas = len(set(trig[0].row_indices))
        assert marcadas < df.height * 0.10, (
            f"marcó {marcadas} de {df.height} filas limpias: {trig[0].examples[:5]}"
        )


def test_cluster_no_fragmenta_una_nube_normal():
    """Regresión: DBSCAN con eps mediano partía cada clase en subgrupos y
    reportaba el 17 % de las filas de un dataset limpio."""
    rep = _corre(_limpio())
    clus = [f for f in rep.findings if f.check_id == "poison.cluster"]
    assert not clus, clus[0].metric if clus else None


# --- Puntaje combinado --------------------------------------------------------


def _f(check_id: str, rows: list[int], scores: list[float]) -> Finding:
    return Finding(
        check_id=check_id,
        severity="medium",
        title="t",
        description="d",
        row_indices=rows,
        row_scores=scores,
    )


def test_la_coincidencia_sube_el_puntaje():
    """Dos detectores que señalan la misma fila valen más que uno solo."""
    findings = [
        _f("poison.knn", [1, 2], [0.5, 0.5]),
        _f("poison.loss", [1, 3], [0.5, 0.5]),
    ]
    c = combine_scores(findings)
    assert c[1].n_detectors == 2
    assert c[1].score > c[2].score
    assert c[1].score > c[3].score


def test_el_combinado_no_queda_por_debajo_del_mejor_detector():
    """Regresión: promediar diluía al detector que acertaba con confianza."""
    findings = [
        _f("poison.knn", [1], [0.9]),
        _f("poison.loss", [2], [0.2]),
    ]
    c = combine_scores(findings)
    assert c[1].score >= 0.9


def test_min_detectors_filtra_los_hallazgos_solitarios():
    findings = [
        _f("poison.knn", [1, 2], [0.9, 0.9]),
        _f("poison.loss", [1], [0.9]),
    ]
    solo_coincidencias = rank_suspects(findings, min_detectors=2)
    assert [s.row for s in solo_coincidencias] == [1]


def test_rank_suspects_ordena_de_mayor_a_menor():
    findings = [_f("poison.knn", [1, 2, 3], [0.2, 0.9, 0.5])]
    orden = [s.row for s in rank_suspects(findings)]
    assert orden == [2, 3, 1]


def test_combine_ignora_hallazgos_sin_filas():
    findings = [Finding(check_id="x", severity="low", title="t", description="d")]
    assert combine_scores(findings) == {}


# --- Separación de módulos ----------------------------------------------------


def test_los_detectores_no_corren_en_una_auditoria_normal():
    rep = run_audit(_ctx(_limpio(200)))
    ids = {f.check_id for f in rep.findings} | set(rep.skipped)
    assert not any(i.startswith("poison.") for i in ids)
