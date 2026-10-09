"""Control de falsos positivos: un dataset sin defectos no debe dar alarmas graves.

El generador es `benchmarks/control_limpio.py`. Este test no exige un semaforo
verde (ver el comentario al final), pero si que ningun check de duplicados,
fuga, atajos o validez invente un problema donde no lo hay.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import vigia

pytest.importorskip("cleanlab")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks"))

from control_limpio import build  # noqa: E402

#: Checks que no deben encontrar nada en un dataset limpio.
DEBEN_ESTAR_LIMPIOS = (
    "dup.",
    "leak.",
    "shortcut.single_feature",
    "validity.",
    "labels.conflict",
    "labels.imbalance",
    "labels.taxonomy",
)


@pytest.fixture(scope="module")
def reporte(tmp_path_factory):
    path = tmp_path_factory.mktemp("control") / "control.parquet"
    build(n=20_000).write_parquet(path)
    ctx = vigia.load(path, split_col="split")
    return vigia.audit(ctx)


def test_el_control_no_inventa_problemas_en_los_checks_deterministas(reporte):
    falsos = [f.check_id for f in reporte.findings if f.check_id.startswith(DEBEN_ESTAR_LIMPIOS)]
    assert falsos == []


def test_los_checks_de_fuga_corrieron_y_no_encontraron_nada(reporte):
    # Si se saltaran, el control no probaria nada sobre ellos.
    for check in ("leak.host", "leak.session", "leak.temporal", "dup.cross_split"):
        assert check not in reporte.skipped, reporte.skipped.get(check)


def test_con_los_roles_autodetectados_se_marcan_como_identificadores(reporte):
    # Si nadie declara timestamp, src_ip y dst_ip, Vigia no sabe que son
    # metadatos y los marca. Es lo correcto: son identificadores hasta que el
    # usuario diga lo contrario.
    graves = [f.check_id for f in reporte.findings if f.severity in ("critical", "high")]
    assert graves == ["shortcut.identifier"]


def test_con_los_roles_declarados_el_control_da_verde(tmp_path):
    path = tmp_path / "control.parquet"
    build(n=20_000).write_parquet(path)
    ctx = vigia.load(
        path,
        split_col="split",
        time_col="timestamp",
        src_ip_col="src_ip",
        dst_ip_col="dst_ip",
    )
    rep = vigia.audit(ctx)
    assert rep.findings == []
    assert rep.traffic_light() == "verde"
