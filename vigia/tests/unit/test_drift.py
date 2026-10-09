"""Módulo 3: métricas de distancia y checks de deriva."""

from __future__ import annotations

import random

import polars as pl
import pytest

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.engine import run_audit
from vigia.drift.checks import (
    ConceptDriftCheck,
    CovariateDriftCheck,
    FeatureDriftCheck,
    PriorDriftCheck,
    SchemaDriftCheck,
)
from vigia.drift.metrics import js_divergence, ks_statistic, psi


def _trafico(
    n: int = 1200,
    seed: int = 0,
    *,
    bytes_mult: float = 1.0,
    ratio_ataque: float = 0.33,
    clase_extra: bool = False,
) -> pl.DataFrame:
    r = random.Random(seed)
    filas = []
    for _ in range(n):
        ataque = r.random() < ratio_ataque
        base = (800.0 if ataque else 120.0) * bytes_mult
        etiqueta = "DDoS" if ataque else "BENIGN"
        if clase_extra and r.random() < 0.15:
            etiqueta = "Cryptominer"
        filas.append(
            {
                "bytes_fwd": base + r.gauss(0, 40),
                "bytes_bwd": base * 0.6 + r.gauss(0, 30),
                "duracion": (2.0 if ataque else 8.0) + r.gauss(0, 0.8),
                "pkts": (40 if ataque else 12) + r.randint(-4, 4),
                "Label": etiqueta,
            }
        )
    return pl.DataFrame(filas)


def _ctx(actual: pl.DataFrame, ref: pl.DataFrame | None) -> AuditContext:
    return AuditContext(
        df=actual, reference=ref, path="lote", sha256="0" * 64, label_col="Label", seed=42
    )


# --- Métricas -----------------------------------------------------------------


def test_psi_es_cero_para_la_misma_distribucion():
    s = pl.Series([float(i) for i in range(1000)])
    assert psi(s, s) < 0.01


def test_psi_crece_al_desplazar_la_distribucion():
    a = pl.Series([float(i) for i in range(1000)])
    poco = pl.Series([float(i) + 50 for i in range(1000)])
    mucho = pl.Series([float(i) + 500 for i in range(1000)])
    assert psi(a, poco) < psi(a, mucho)
    assert psi(a, mucho) > 0.25


def test_ks_entre_cero_y_uno():
    a = pl.Series([float(i) for i in range(500)])
    b = pl.Series([float(i) + 1000 for i in range(500)])
    assert ks_statistic(a, a) == pytest.approx(0.0, abs=0.01)
    assert ks_statistic(a, b) == pytest.approx(1.0, abs=0.01)


def test_js_detecta_una_categoria_nueva():
    a = pl.Series(["x"] * 50 + ["y"] * 50)
    b = pl.Series(["x"] * 50 + ["y"] * 30 + ["z"] * 20)
    assert js_divergence(a, a) == pytest.approx(0.0, abs=1e-9)
    assert js_divergence(a, b) > 0.05


def test_las_metricas_toleran_series_vacias():
    vacia = pl.Series([], dtype=pl.Float64)
    llena = pl.Series([1.0, 2.0, 3.0])
    assert psi(vacia, llena) == 0.0
    assert ks_statistic(vacia, llena) == 0.0
    assert js_divergence(pl.Series([], dtype=pl.Utf8), pl.Series(["a"])) == 0.0


# --- Sin referencia no corren -------------------------------------------------


@pytest.mark.parametrize(
    "check",
    [
        SchemaDriftCheck(),
        FeatureDriftCheck(),
        PriorDriftCheck(),
        CovariateDriftCheck(),
        ConceptDriftCheck(),
    ],
    ids=lambda c: c.id,
)
def test_sin_referencia_se_saltan(check):
    with pytest.raises(CheckSkipped, match="referencia"):
        check.run(_ctx(_trafico(100), None))


# --- Detectan la deriva sembrada ----------------------------------------------


def test_control_sin_deriva_no_reporta_nada():
    """Dos muestras del mismo generador no son deriva.

    Es el control de falsos positivos del módulo: si un remuestreo dispara
    una alerta, la herramienta pediría reentrenar todas las semanas sin
    motivo y dejarían de hacerle caso.
    """
    rep = run_audit(_ctx(_trafico(seed=2), _trafico(seed=1)), module="drift")
    assert rep.findings == [], [f.title for f in rep.findings]


def test_detecta_deriva_de_caracteristicas():
    rep = run_audit(_ctx(_trafico(seed=2, bytes_mult=2.0), _trafico(seed=1)), module="drift")
    ids = {f.check_id for f in rep.findings}
    assert "drift.feature" in ids


def test_detecta_una_clase_nueva():
    findings = PriorDriftCheck().run(_ctx(_trafico(seed=2, clase_extra=True), _trafico(seed=1)))
    assert len(findings) == 1
    assert findings[0].metric["n_clases_nuevas"] == 1.0
    assert findings[0].severity == "high"


def test_detecta_el_cambio_de_proporcion():
    findings = PriorDriftCheck().run(_ctx(_trafico(seed=2, ratio_ataque=0.85), _trafico(seed=1)))
    assert len(findings) == 1
    assert findings[0].metric["js_divergence"] > 0.05


def test_columna_faltante_es_critica():
    """Si falta una característica, el modelo directamente no puede predecir."""
    findings = SchemaDriftCheck().run(_ctx(_trafico(seed=2).drop("pkts"), _trafico(seed=1)))
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].metric["n_faltantes"] == 1.0


def test_columna_nueva_es_menos_grave():
    """Una columna de más solo se ignora; una de menos rompe el modelo."""
    actual = _trafico(seed=2).with_columns(pl.lit(1).alias("nueva"))
    findings = SchemaDriftCheck().run(_ctx(actual, _trafico(seed=1)))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].metric["n_nuevas"] == 1.0


def test_esquema_identico_no_reporta():
    assert SchemaDriftCheck().run(_ctx(_trafico(seed=2), _trafico(seed=1))) == []


def test_covariate_drift_con_conjuntos_separables():
    pytest.importorskip("sklearn")
    findings = CovariateDriftCheck().run(_ctx(_trafico(seed=2, bytes_mult=3.0), _trafico(seed=1)))
    assert len(findings) == 1
    assert findings[0].metric["auc"] > 0.75
    # La columna que más cambió tiene que aparecer entre las que distinguen.
    columnas = {e["columna"] for e in findings[0].examples}
    assert "bytes_fwd" in columnas


def test_covariate_drift_se_salta_con_pocas_filas():
    pytest.importorskip("sklearn")
    with pytest.raises(CheckSkipped, match="50 filas"):
        CovariateDriftCheck().run(_ctx(_trafico(20, seed=2), _trafico(20, seed=1)))


def _concepto(n: int, seed: int, *, invertido: bool) -> pl.DataFrame:
    """Mismo P(X); la etiqueta depende de x1 + x2 > 0, o de lo contrario."""
    r = random.Random(seed)
    filas = []
    for _ in range(n):
        x1, x2 = r.gauss(0, 1), r.gauss(0, 1)
        ataque = (x1 + x2 > 0) != invertido
        filas.append({"x1": x1, "x2": x2, "Label": "ATTACK" if ataque else "BENIGN"})
    return pl.DataFrame(filas)


def test_concepto_invertido_no_da_verde():
    """Caso N de la auditoria: P(X) no cambia y la etiqueta se invierte. El
    viejo `drift.concept` (validacion adversaria) no usaba la etiqueta y el
    semaforo daba verde con "no hace falta reentrenar" (SCI-03)."""
    pytest.importorskip("sklearn")
    rep = run_audit(
        _ctx(_concepto(600, 2, invertido=True), _concepto(600, 1, invertido=False)),
        module="drift",
    )
    ids = {f.check_id for f in rep.findings}
    assert "drift.concept" in ids
    assert rep.traffic_light() == "rojo"


def test_concepto_estable_no_reporta():
    pytest.importorskip("sklearn")
    rep = run_audit(
        _ctx(_concepto(600, 2, invertido=False), _concepto(600, 1, invertido=False)),
        module="drift",
    )
    assert "drift.concept" not in {f.check_id for f in rep.findings}
    assert "drift.concept" not in rep.skipped


def test_concepto_sin_etiqueta_en_el_lote_se_salta_y_lo_dice():
    pytest.importorskip("sklearn")
    rep = run_audit(
        _ctx(_concepto(500, 2, invertido=True).drop("Label"), _concepto(500, 1, invertido=False)),
        module="drift",
    )
    assert "etiqueta" in rep.skipped["drift.concept"]


def _raro(n: int, seed: int, *, corrimiento: float = 0.0, p_ataque: float = 0.04) -> pl.DataFrame:
    """Ataque raro (4 %) que se separa del trafico normal en x1 y x2.

    `corrimiento` mueve los ataques hacia la zona normal: es deriva de concepto
    real (el modelo deja de reconocerlos), sin tocar al trafico normal."""
    import numpy as np

    r = np.random.default_rng(seed)
    y = np.where(r.random(n) < p_ataque, "attack", "benign")
    x1 = r.normal(0, 1, n) + (y == "attack") * (2.0 - corrimiento)
    x2 = r.normal(0, 1, n) + (y == "attack") * (1.8 - corrimiento)
    return pl.DataFrame({"x1": x1, "x2": x2, "x3": r.normal(0, 1, n), "Label": y})


def _concepto_de(lote: pl.DataFrame, ref: pl.DataFrame, seed: int = 0):
    ctx = _ctx(lote, ref)
    ctx.seed = seed
    return run_audit(ctx, checks="drift.concept", module="drift")


@pytest.mark.parametrize("seed", [0, 1])
def test_lote_de_una_sola_clase_de_la_misma_distribucion_no_reporta(seed):
    """Un lote con solo ataques, de la MISMA distribucion que la referencia, daba
    critico: la exactitud balanceada de un lote de una clase es el recall de esa
    clase, y se la comparaba con el promedio de todas (VERIFICACION-1.0.md, VER-03)."""
    pytest.importorskip("sklearn")
    lote = _raro(4000, 100 + seed).filter(pl.col("Label") == "attack")
    rep = _concepto_de(lote, _raro(4000, seed), seed)
    assert rep.findings == [], [(f.severity, f.metric) for f in rep.findings]


@pytest.mark.parametrize("seed", [0, 1])
def test_referencia_con_duplicados_x4_de_la_misma_distribucion_no_reporta(seed):
    """Con cada fila repetida 4 veces, la validacion cruzada ponia las copias de una
    fila en el entrenamiento y en la prueba y sobrestimaba a la referencia: el lote,
    sin copias, parecia derivar (VERIFICACION-1.0.md, VER-04)."""
    pytest.importorskip("sklearn")
    ref = pl.concat([_raro(1000, seed)] * 4)
    rep = _concepto_de(_raro(4000, 100 + seed), ref, seed)
    assert rep.findings == [], [(f.severity, f.metric) for f in rep.findings]


def test_lote_de_una_clase_con_deriva_real_en_esa_clase_si_reporta():
    """El caso que un lote de una clase si tiene que ver: los ataques llegan
    corridos hacia la zona normal y el modelo ya no los reconoce."""
    pytest.importorskip("sklearn")
    lote = _raro(5000, 100, corrimiento=1.6).filter(pl.col("Label") == "attack")
    rep = _concepto_de(lote, _raro(4000, 0))
    hallazgos = [f for f in rep.findings if f.check_id == "drift.concept"]
    assert hallazgos, rep.skipped
    assert "attack" in hallazgos[0].title


def test_las_filas_del_lote_que_estan_en_la_referencia_no_inflan_el_resultado():
    """Una fila identica a una de la referencia la memorizo el modelo: acierta sin
    que eso diga nada de la relacion con la etiqueta. Se excluyen del lote, y si no
    queda nada con que evaluar el check se salta diciendolo."""
    pytest.importorskip("sklearn")
    ref = _raro(2000, 0, p_ataque=0.3)
    rep = _concepto_de(ref, ref)
    assert "referencia" in rep.skipped["drift.concept"]


def test_ninguna_clase_del_lote_con_filas_suficientes_se_salta_con_motivo():
    pytest.importorskip("sklearn")
    base = _raro(1000, 100, p_ataque=0.5)
    lote = pl.concat(
        [base.filter(pl.col("Label") == c).head(29) for c in ("attack", "benign")]
    )  # 58 filas en total, pero ninguna clase llega a 30
    rep = _concepto_de(lote, _raro(1000, 0, p_ataque=0.5))
    assert "filas" in rep.skipped["drift.concept"]


# --- Separación de módulos ----------------------------------------------------


def test_los_checks_de_deriva_no_corren_en_una_auditoria():
    rep = run_audit(_ctx(_trafico(200), _trafico(200, seed=9)))
    ids = {f.check_id for f in rep.findings} | set(rep.skipped)
    assert not any(i.startswith("drift.") for i in ids)


def test_el_umbral_de_psi_es_configurable():
    ctx = _ctx(_trafico(seed=2, bytes_mult=1.15), _trafico(seed=1))
    ctx.config["psi_threshold"] = 999.0
    assert FeatureDriftCheck().run(ctx) == []
