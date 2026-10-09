"""Auditoría de punta a punta: motor, reporte y CLI."""

from __future__ import annotations

import json

import polars as pl
import pytest
from typer.testing import CliRunner

import vigia
from vigia.cli import app
from vigia.core.engine import run_audit
from vigia.core.findings import Finding, Report
from vigia.core.registry import all_checks, select
from vigia.report import render_html, write_report

runner = CliRunner()


@pytest.fixture
def dirty_csv(tmp_path):
    """CSV con varios errores sembrados: duplicado cruzado, atajo y fuga por host."""
    rows = {
        " Source IP": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3"],
        "Duration": [1.0, 1.0, 2.5, 1.0, 3.0],
        "Constante": [7, 7, 7, 7, 7],
        "Label": ["ATTACK", "ATTACK", "BENIGN", "ATTACK", "BENIGN"],
        "split": ["train", "train", "train", "test", "test"],
    }
    path = tmp_path / "flows.csv"
    pl.DataFrame(rows).write_csv(path)
    return path


def test_todos_los_checks_estan_registrados():
    ids = {c.id for c in all_checks()}
    # Los 5 checks de la Fase 0 del documento maestro.
    assert {
        "dup.exact",
        "validity.nan_inf",
        "shortcut.single_feature",
        "leak.temporal",
        "leak.host",
    } <= ids


def test_select_por_categoria():
    assert {c.id for c in select("leak")} == {"leak.temporal", "leak.host", "leak.session"}
    assert [c.id for c in select("dup.exact")] == ["dup.exact"]
    with pytest.raises(KeyError):
        select("no.existe")


def test_select_acepta_un_id_secundario():
    """`dup.class_ratio` aparece en los reportes: hay que poder pedirlo."""
    assert [c.id for c in select("dup.class_ratio")] == ["dup.exact"]


def test_cli_checks_lista_los_ids_secundarios():
    result = runner.invoke(app, ["checks"])
    assert "dup.class_ratio" in result.output


def test_un_check_roto_no_tumba_la_auditoria(clean_ctx, monkeypatch):
    class Explota:
        id = "test.explota"
        name = "Check que falla"
        category = "test"
        applies_to = {"tabular"}

        def run(self, ctx):
            raise RuntimeError("boom")

    monkeypatch.setattr("vigia.core.engine.select", lambda spec, module=None: [Explota()])
    report = run_audit(clean_ctx)
    assert report.findings == []
    # Un bug del check va a `errors`, no a `skipped`: no es "no aplicaba".
    assert "boom" in report.errors["test.explota"]
    assert "test.explota" not in report.skipped


def _reporte(**kw):
    base = dict(
        dataset_path="x.csv", dataset_sha256="abc", n_rows=1, n_cols=1, vigia_version="1", seed=42
    )
    return Report(**{**base, **kw})


def test_un_check_que_falla_no_deja_el_semaforo_verde_ni_gris():
    """Sin otros hallazgos, un crash salia gris ("faltaba una columna") en el
    mismo diccionario que los saltos por diseño (AUDITORIA-1.0.md, COR-05)."""
    assert _reporte(errors={"labels.conflict": "TypeError: x"}).traffic_light() == "rojo"
    # Un salto por diseño sigue dando gris, y sin nada, verde.
    assert _reporte(skipped={"leak.host": "falta"}).traffic_light() == "gris"
    assert _reporte().traffic_light() == "verde"


def test_el_html_muestra_los_errores_aparte_y_no_dice_que_todo_corrio():
    from vigia.report.render import render_html

    html = render_html(_reporte(errors={"labels.conflict": "TypeError: <b>x</b>"}))
    assert "Checks que fallaron" in html
    assert "labels.conflict" in html
    # El texto del error viene de una excepcion: se escapa como todo lo demas.
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html
    assert "todos se ejecutaron" not in html

    # Sin errores la seccion no aparece.
    assert "Checks que fallaron" not in render_html(_reporte())


def test_el_json_lleva_errors_n_errors_y_schema_version():
    d = _reporte(errors={"a.b": "RuntimeError: x"}, skipped={"c.d": "falta"}).to_dict()
    assert d["schema_version"] == "1"
    assert d["errors"] == {"a.b": "RuntimeError: x"}
    assert d["summary"]["n_errors"] == 1
    assert d["summary"]["n_skipped"] == 1  # los saltos no se mezclan con los errores
    assert d["skipped"] == {"c.d": "falta"}
    # Lo que ya era contrato sigue estando: solo se agregaron claves.
    assert {"dataset", "run", "summary", "findings", "skipped"} <= d.keys()


def test_auditoria_completa_sobre_csv_sucio(dirty_csv, tmp_path):
    ctx = vigia.load(dirty_csv)
    # Detección automática de columnas por nombre.
    assert ctx.label_col == "Label"
    assert ctx.split_col == "split"
    assert ctx.src_ip_col == "Source IP"  # el espacio inicial fue normalizado

    report = vigia.audit(ctx)
    ids = {f.check_id for f in report.findings}
    assert "dup.cross_split" in ids
    assert "leak.host" in ids
    assert "validity.constant" in ids
    assert report.traffic_light() == "rojo"
    assert report.exceeds("critical")

    html_path, json_path = write_report(report, tmp_path / "out")
    assert html_path.exists() and json_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["summary"]["traffic_light"] == "rojo"
    assert data["dataset"]["n_rows"] == 5
    assert len(data["findings"]) == len(report.findings)
    # El JSON debe estar ordenado de más grave a menos grave.
    severidades = [f["severity"] for f in data["findings"]]
    assert severidades == sorted(
        severidades, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s)
    )


def test_dataset_limpio_no_genera_hallazgos_graves(clean_flows, tmp_path):
    """Control de falsos positivos (experimento 6 de la sección 16.2)."""
    path = tmp_path / "clean.csv"
    clean_flows.write_csv(path)
    ctx = vigia.load(
        path,
        time_col="moment",
        src_ip_col="host",
        dst_ip_col="peer",
        src_port_col="sport",
        dst_port_col="dport",
        protocol_col="proto",
    )
    report = vigia.audit(ctx)
    assert not report.exceeds("high"), [f.title for f in report.findings]

    # `labels.noise` es el único que no puede correr acá, y por una razón que
    # forma parte del diseño del fixture: sus características son
    # deliberadamente independientes de la etiqueta, así que el modelo auxiliar
    # no supera a la clase mayoritaria y el check se abstiene. Abstenerse es lo
    # correcto: sin señal, lo que el modelo no acierta no es ruido de etiqueta.
    assert set(report.skipped) <= {"labels.noise"}, report.skipped
    assert report.traffic_light() in ("verde", "amarillo", "gris")


def test_html_escapa_contenido_del_dataset():
    report = Report(
        dataset_path="x.csv",
        dataset_sha256="abc",
        n_rows=1,
        n_cols=1,
        vigia_version="0.1.0",
        seed=42,
        findings=[
            Finding(
                check_id="t.x",
                severity="high",
                title="<script>alert(1)</script>",
                description="d",
                examples=[{"col": "<img onerror=x>"}],
                recommendation="r",
            )
        ],
    )
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_escapa_comillas_del_dataset():
    """Las comillas también: un nombre de columna hostil no debe poder salirse
    de un atributo si mañana alguien interpola uno."""
    report = Report(
        dataset_path="x.csv",
        dataset_sha256="abc",
        n_rows=1,
        n_cols=1,
        vigia_version="0.1.0",
        seed=42,
        findings=[
            Finding(
                check_id="t.x",
                severity="high",
                title='" onfocus="alert(1)',
                description="d",
                examples=[{'col" onerror="x': "v"}],
                recommendation="r",
            )
        ],
    )
    html = render_html(report)
    assert 'onfocus="alert(1)' not in html
    assert 'onerror="x' not in html
    assert "&quot;" in html


def test_semaforo_gris_cuando_hay_checks_saltados():
    """Sin hallazgos pero sin cobertura completa no es verde.

    Los checks que se saltan son los que dependen de la etiqueta o del split,
    o sea los que detectan fuga y duplicados cruzados. Dar verde le diría a
    quien tiene la columna mal nombrada que su dataset está limpio.
    """
    report = Report(
        dataset_path="x.csv",
        dataset_sha256="abc",
        n_rows=1,
        n_cols=1,
        vigia_version="0.1.0",
        seed=42,
        skipped={"leak.host": "requiere 'split_col'"},
    )
    assert report.traffic_light() == "gris"
    assert report.to_dict()["summary"]["n_skipped"] == 1


def test_semaforo_verde_solo_con_cobertura_completa():
    report = Report(
        dataset_path="x.csv",
        dataset_sha256="abc",
        n_rows=1,
        n_cols=1,
        vigia_version="0.1.0",
        seed=42,
    )
    assert report.traffic_light() == "verde"


def test_dataset_sin_etiqueta_no_da_verde(tmp_path):
    """Caso real: un CSV cuya etiqueta no se detecta."""
    path = tmp_path / "sin_label.csv"
    pl.DataFrame({"colA": [1, 2, 3], "colB": [4.0, 5.0, 6.0]}).write_csv(path)
    report = vigia.audit(vigia.load(path))
    assert report.findings == []
    assert report.skipped
    assert report.traffic_light() == "gris"


def test_finding_rechaza_severidad_invalida():
    with pytest.raises(ValueError):
        Finding(check_id="t", severity="urgente", title="t", description="d")  # type: ignore[arg-type]


def test_finding_recorta_ejemplos_a_diez():
    f = Finding(
        check_id="t",
        severity="low",
        title="t",
        description="d",
        examples=[{"i": i} for i in range(50)],
    )
    assert len(f.examples) == 10


# --- CLI ---------------------------------------------------------------------


def test_cli_audit_genera_reporte(dirty_csv, tmp_path):
    out = tmp_path / "rep"
    result = runner.invoke(app, ["audit", str(dirty_csv), "--report", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "report.html").exists()
    assert "ROJO" in result.output


def test_cli_fail_on_critical_sale_con_codigo_1(dirty_csv):
    result = runner.invoke(app, ["audit", str(dirty_csv), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_cli_fail_on_invalido(dirty_csv):
    result = runner.invoke(app, ["audit", str(dirty_csv), "--fail-on", "urgente"])
    assert result.exit_code == 2


def test_cli_checks_invalido_sale_con_codigo_2(dirty_csv):
    """Un id inexistente es un error de uso, no un traceback."""
    result = runner.invoke(app, ["audit", str(dirty_csv), "--checks", "no.existe"])
    assert result.exit_code == 2
    assert "no.existe" in result.output


def test_cli_archivo_inexistente(tmp_path):
    result = runner.invoke(app, ["audit", str(tmp_path / "no_existe.csv")])
    assert result.exit_code == 2


def test_cli_checks_lista_los_ids():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0
    assert "leak.temporal" in result.output


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert vigia.__version__ in result.output


def _romper_dup_exact(monkeypatch):
    from vigia.core.registry import get

    def boom(ctx):
        raise RuntimeError("kaput")

    monkeypatch.setattr(get("dup.exact"), "run", boom)


def test_cli_un_check_que_falla_sale_con_3_y_lo_dice(dirty_csv, tmp_path, monkeypatch):
    """Un check roto salia con 0 y figuraba entre los "no ejecutados"
    (AUDITORIA-1.0.md, COR-05). El 1 sigue siendo "hay hallazgos"."""
    _romper_dup_exact(monkeypatch)
    out = tmp_path / "rep"
    result = runner.invoke(
        app, ["audit", str(dirty_csv), "--checks", "dup.exact", "--report", str(out)]
    )
    assert result.exit_code == 3, result.output
    assert "dup.exact" in result.output and "kaput" in result.output
    assert "no ejecutados" not in result.output  # no se mezcla con los saltos
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["n_errors"] == 1


def test_cli_con_errores_y_sin_hallazgos_no_dice_sin_hallazgos_bajo_un_semaforo_rojo(
    dirty_csv, monkeypatch
):
    """Con un check roto y ningun hallazgo la CLI imprimia "Semaforo: ROJO" y, en la
    linea siguiente, "sin hallazgos" en verde (VERIFICACION-1.0.md, VER-06)."""
    _romper_dup_exact(monkeypatch)
    result = runner.invoke(app, ["audit", str(dirty_csv), "--checks", "dup.exact"])
    assert "ROJO" in result.output
    assert "sin hallazgos" not in result.output.lower(), result.output


def test_cli_con_hallazgos_que_alcanzan_fail_on_gana_el_1(dirty_csv, monkeypatch):
    _romper_dup_exact(monkeypatch)
    result = runner.invoke(
        app,
        ["audit", str(dirty_csv), "--checks", "dup.exact,dup.cross_split", "--fail-on", "critical"],
    )
    assert result.exit_code == 1, result.output


def test_cli_un_error_inesperado_sale_con_3_y_sin_traceback(dirty_csv, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("kaput")

    monkeypatch.setattr("vigia.load", boom)
    result = runner.invoke(app, ["audit", str(dirty_csv)])
    assert result.exit_code == 3, result.output
    assert "Error inesperado" in result.output and "kaput" in result.output
    assert "Traceback" not in result.output

    # Para diagnosticar, VIGIA_DEBUG deja pasar la excepcion original.
    monkeypatch.setenv("VIGIA_DEBUG", "1")
    result = runner.invoke(app, ["audit", str(dirty_csv)])
    assert isinstance(result.exception, RuntimeError)


def test_cli_una_columna_inexistente_es_un_error_de_uso(dirty_csv):
    """`--label-col` mal escrito es entrada del usuario: codigo 2, no 1 ni 3."""
    result = runner.invoke(app, ["audit", str(dirty_csv), "--streaming", "--label-col", "Nada"])
    assert result.exit_code == 2, result.output
    assert "Nada" in result.output


def test_cli_drift_con_un_check_roto_no_dice_que_no_hace_falta_reentrenar(tmp_path, monkeypatch):
    from vigia.core.registry import get

    def boom(ctx):
        raise RuntimeError("kaput")

    monkeypatch.setattr(get("drift.schema"), "run", boom)
    df = pl.DataFrame({"a": [1.0, 2.0, 3.0] * 20, "Label": ["x", "y", "x"] * 20})
    a, b = tmp_path / "a.parquet", tmp_path / "b.parquet"
    df.write_parquet(a)
    df.write_parquet(b)
    result = runner.invoke(app, ["drift", str(a), "--reference", str(b)])
    assert result.exit_code == 3, result.output
    assert "no hace falta reentrenar" not in result.output


def test_la_version_sale_de_los_metadatos_y_coincide_con_pyproject():
    """La version vivia escrita a mano en `pyproject.toml` y en
    `vigia/__init__.py`; un tag mal puesto o un descuido publicaban un paquete
    que decia otra version (AUDITORIA-1.0.md, CI-01)."""
    import tomllib
    from importlib.metadata import version
    from pathlib import Path

    pyproject = Path(__file__).parents[2] / "pyproject.toml"
    declarada = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert vigia.__version__ == version("vigia-nids") == declarada


def test_sin_el_paquete_instalado_la_version_tiene_un_respaldo():
    """Si los metadatos no estan (se importa desde un arbol sin instalar), la
    importacion no puede fallar: queda una version que se reconoce como falsa."""
    import subprocess
    import sys

    codigo = (
        "import importlib.metadata as m\n"
        "def v(nombre):\n"
        "    raise m.PackageNotFoundError(nombre)\n"
        "m.version = v\n"
        "import vigia\n"
        "print(vigia.__version__)\n"
    )
    r = subprocess.run([sys.executable, "-c", codigo], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0.0.0+desconocida"


def test_la_version_por_defecto_es_la_del_paquete(tmp_path):
    """USO.md enseña `run_audit(ctx, module="poison")` sin `version`: el reporte
    decía `vigia_version: 0.1.0` (AUDITORIA-1.0.md, COR-15)."""
    import polars as pl

    from vigia.core.context import AuditContext
    from vigia.core.engine import run_audit
    from vigia.core.streaming import run_streaming_audit

    df = pl.DataFrame({"a": [1, 2, 3], "label": ["x", "y", "x"]})
    assert run_audit(AuditContext(df=df, label_col="label")).vigia_version == vigia.__version__

    p = tmp_path / "d.csv"
    df.write_csv(p)
    assert run_streaming_audit(p, label_col="label").vigia_version == vigia.__version__


def test_fix_se_niega_a_sobrescribir_la_entrada(tmp_path):
    """El original nunca se toca: con `--out` igual a la entrada se leía todo y
    se pisaba el original (AUDITORIA-1.0.md, COR-16)."""
    import polars as pl

    src = tmp_path / "flows.csv"
    pl.DataFrame({"a": [1, 1, 2], "label": ["x", "x", "y"]}).write_csv(src)
    antes = src.read_bytes()

    for destino in (src, tmp_path / "." / "flows.csv"):
        result = runner.invoke(
            app, ["fix", str(src), "--apply", "drop_duplicates", "--out", str(destino)]
        )
        assert result.exit_code == 2, result.output
        assert "entrada" in result.output
    assert src.read_bytes() == antes


def test_fix_sin_ninguna_correccion_aplicable_es_un_error_de_uso(tmp_path):
    """El 1 significa "hay hallazgos que alcanzan --fail-on"; que ninguna
    correccion se pueda aplicar es un error de uso (2), segun ARQUITECTURA.md
    (AUDITORIA-1.0.md, seccion 8, problema nuevo 1)."""
    import polars as pl

    src = tmp_path / "flows.csv"
    pl.DataFrame({"a": [1, 2, 3], "label": ["x", "y", "x"]}).write_csv(src)
    out = tmp_path / "limpio.csv"

    result = runner.invoke(app, ["fix", str(src), "--apply", "temporal_split", "--out", str(out)])
    assert result.exit_code == 2, result.output
    assert "Ninguna corrección" in result.output
    assert not out.exists()


# --- Separación por módulo ----------------------------------------------------


def test_audit_solo_corre_los_checks_del_auditor():
    """Los de envenenamiento y deriva no deben ensuciar una auditoría.

    Sin esta separación, `vigia audit` los correría y los reportaría como
    saltados por motivos que no dicen nada sobre el dataset.
    """
    from vigia.core.registry import all_checks, module_of

    assert all(module_of(c) == "auditor" for c in all_checks())
    # Sin filtro se ven todos los registrados, cualquiera sea su módulo.
    assert len(all_checks(None)) >= len(all_checks())


def test_finding_acepta_puntaje_por_fila():
    """El módulo de envenenamiento combina puntajes de varios detectores."""
    f = Finding(
        check_id="poison.x",
        severity="high",
        title="t",
        description="d",
        row_indices=[3, 7],
        row_scores=[0.9, 0.4],
    )
    assert f.row_scores == [0.9, 0.4]
    # No va al informe: serían miles de números que nadie lee.
    assert "row_scores" not in f.to_dict()


def test_finding_rechaza_puntajes_desalineados():
    """Un puntaje sin su fila no se puede combinar con el de otro detector."""
    with pytest.raises(ValueError, match="alineados"):
        Finding(
            check_id="poison.x",
            severity="high",
            title="t",
            description="d",
            row_indices=[1, 2, 3],
            row_scores=[0.5],
        )


# --- VER-01: la CLI no puede depender de lo que solo trae un extra -------------


def test_la_cli_solo_importa_dependencias_del_nucleo():
    """`typer` 0.27 dejo de depender de `click`, y `cli.py` lo importaba: con la
    rueda instalada sin extras, `vigia` ni arrancaba (VERIFICACION-1.0.md, VER-01).
    En el CI `click` llegaba por `uvicorn` y nadie lo veia. Los imports de nivel de
    modulo de `cli.py` tienen que ser de la biblioteca estandar, de `vigia` o de las
    dependencias que declara `pyproject.toml`."""
    import ast
    import sys
    import tomllib
    from pathlib import Path

    raiz = Path(__file__).resolve().parents[2]
    declaradas = {
        d.split(">")[0].split("=")[0].split("<")[0].split("[")[0].strip().lower().replace("-", "_")
        for d in tomllib.loads((raiz / "pyproject.toml").read_text(encoding="utf-8"))["project"][
            "dependencies"
        ]
    }
    # `pyyaml` se importa como `yaml`.
    permitidos = set(sys.stdlib_module_names) | {"vigia", "yaml"} | declaradas
    arbol = ast.parse((raiz / "src" / "vigia" / "cli.py").read_text(encoding="utf-8"))
    ajenos = set()
    for nodo in arbol.body:
        if isinstance(nodo, ast.Import):
            ajenos |= {a.name.split(".")[0] for a in nodo.names}
        elif isinstance(nodo, ast.ImportFrom) and nodo.level == 0 and nodo.module:
            ajenos.add(nodo.module.split(".")[0])
    assert ajenos - permitidos == set(), f"cli.py importa fuera del nucleo: {ajenos - permitidos}"


def test_un_error_de_uso_de_typer_dentro_de_un_comando_no_es_un_defecto():
    """`typer.BadParameter` no es subclase de `click.ClickException` en typer 0.27
    (trae su propio click), asi que la guarda lo tomaba por un error inesperado y
    salia con 3 en vez de 2."""
    import typer

    from vigia.cli import _guarded

    mini = typer.Typer()

    @mini.command()
    @_guarded
    def uso() -> None:
        raise typer.BadParameter("falta algo")

    @mini.command()
    @_guarded
    def roto() -> None:
        raise RuntimeError("bug")

    assert runner.invoke(mini, ["uso"]).exit_code == 2
    assert runner.invoke(mini, ["roto"]).exit_code == 3


# --- VER-07: los numeros de la documentacion salen del registro -----------------


def test_la_documentacion_cuenta_los_checks_que_hay():
    """README, PLAN y CHANGELOG decian 26 (17 + 4 + 5) con 25 reales (16 + 4 + 5):
    el 17 ya venia mal de antes y se le sumo uno encima (VERIFICACION-1.0.md,
    VER-07). El numero de la documentacion se compara con el registro."""
    import re
    from collections import Counter
    from pathlib import Path

    from vigia.core.registry import all_checks, module_of

    raiz = Path(__file__).resolve().parents[2]
    por_modulo = Counter(module_of(c) for c in all_checks(None))
    total = sum(por_modulo.values())

    readme = (raiz / "README.md").read_text(encoding="utf-8")
    m = re.search(
        r"(\d+) checks \((\d+) del auditor, (\d+) de envenenamiento y (\d+) de deriva\)", readme
    )
    assert m, "el README ya no dice cuantos checks hay"
    assert tuple(map(int, m.groups())) == (
        total,
        por_modulo["auditor"],
        por_modulo["poison"],
        por_modulo["drift"],
    )

    plan = (raiz / "docs" / "PLAN.md").read_text(encoding="utf-8")
    m = re.search(r"Módulo 1 \(auditor\) \| (\d+) checks", plan)
    assert m and int(m.group(1)) == por_modulo["auditor"]

    changelog = (raiz / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(r"\((\d+) en total\)", changelog)
    assert m and int(m.group(1)) == total
