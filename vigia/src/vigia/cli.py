"""CLI de Vigía (sección 14.1)."""

from __future__ import annotations

import functools
import os
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import polars as pl
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

import vigia
from vigia.core.findings import SEVERITY_ORDER, Report
from vigia.core.registry import all_checks
from vigia.profiles import ProfileNotFound
from vigia.report import write_report

app = typer.Typer(
    name="vigia",
    help="Control de calidad continuo para los datos de modelos de ciberseguridad.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_LIGHT_STYLE = {
    "rojo": "bold red",
    "amarillo": "bold yellow",
    "verde": "bold green",
    "gris": "bold bright_black",
}
_SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _print_summary(report: Report) -> None:
    light = report.traffic_light()
    console.print()
    console.print(
        f"Semáforo: [{_LIGHT_STYLE[light]}]{light.upper()}[/]  "
        f"· {report.n_rows:,} filas × {report.n_cols} columnas"
    )

    counts = report.counts()
    # Con un check roto "sin hallazgos" en verde contradice al semáforo rojo
    # (VERIFICACION-1.0.md, VER-06): no se puede decir nada del dataset todavía.
    sin_hallazgos = (
        "[red]ningún hallazgo, pero el reporte está incompleto[/]"
        if report.errors
        else "[green]sin hallazgos[/]"
    )
    console.print(
        "  ".join(f"[{_SEV_STYLE[s]}]{s}: {counts[s]}[/]" for s in SEVERITY_ORDER if counts[s])
        or sin_hallazgos
    )

    if light == "gris":
        console.print(
            f"[bright_black]Sin hallazgos, pero {len(report.skipped)} check(s) no se "
            "ejecutaron: el dataset no quedó revisado del todo. Revisá la lista de "
            "abajo antes de darlo por limpio.[/]"
        )

    if report.findings:
        table = Table(show_header=True, header_style="dim", box=None, padding=(0, 2, 0, 0))
        table.add_column("Sev")
        table.add_column("Check")
        table.add_column("Hallazgo")
        table.add_column("Filas", justify="right")
        for f in report.sorted_findings():
            table.add_row(
                f"[{_SEV_STYLE[f.severity]}]{f.severity}[/]",
                f"[dim]{f.check_id}[/]",
                f.title,
                f"{f.affected_rows:,}" if f.affected_rows else "-",
            )
        console.print()
        console.print(table)

    if report.errors:
        console.print()
        console.print(
            "[bold red]Checks que fallaron por un error interno[/] "
            "[red](un defecto de Vigía, no del dataset: el reporte está incompleto):[/]"
        )
        for cid, error in sorted(report.errors.items()):
            console.print(f"  [red]{cid}: {escape(error)}[/]")

    if report.skipped:
        console.print()
        console.print("[dim]Checks no ejecutados:[/]")
        for cid, reason in sorted(report.skipped.items()):
            console.print(f"  [dim]{cid}: {escape(reason)}[/]")


#: Código de salida cuando la herramienta falló (un check lanzó una excepción o
#: hubo un error inesperado). El 1 sigue siendo "hay hallazgos que alcanzan
#: --fail-on" y el 2, un error de uso; en CI distinguir los tres importa: un
#: dataset con problemas no es un comando mal escrito ni un bug de Vigía
#: (AUDITORIA-1.0.md, COR-05 y COR-08).
EXIT_INTERNAL_ERROR = 3


def _exit_if_errors(report: Report) -> None:
    """Sale con 3 si algún check falló: el reporte está incompleto.

    Se llama después de comprobar `--fail-on`, así que los hallazgos que ya
    rompen el build siguen saliendo con 1.
    """
    if report.errors:
        console.print(
            f"\n[red]{len(report.errors)} check(s) fallaron por un error interno: el "
            "reporte está incompleto y no se puede dar por limpio.[/]"
        )
        raise typer.Exit(EXIT_INTERNAL_ERROR)


def _guarded(fn: Callable[..., None]) -> Callable[..., None]:
    """Convierte una excepción inesperada en un mensaje y un código de salida.

    Sin esto salía el traceback de Typer con código 1, el mismo que "hay
    hallazgos": en CI un bug de Vigía rompía el build como si el dataset
    estuviera mal. Los errores de uso ya manejados (`typer.Exit`, `typer.Abort` y
    las excepciones de click) pasan tal cual. `VIGIA_DEBUG=1` deja pasar la
    excepción original para diagnosticar.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except (typer.Exit, typer.Abort):
            raise
        except Exception as exc:
            # Un error de uso (`typer.BadParameter`, `click.UsageError`...) ya sabe
            # mostrarse y con que codigo salir. No se nombra `click`: typer 0.27 dejo
            # de depender de el y trae el suyo, con clases que no son las de `click`
            # (VERIFICACION-1.0.md, VER-01), asi que se reconoce por lo que expone.
            if hasattr(exc, "format_message") and hasattr(exc, "exit_code"):
                raise
            if os.environ.get("VIGIA_DEBUG"):
                raise
            detalle = escape(str(exc).strip().splitlines()[0]) if str(exc).strip() else ""
            if isinstance(exc, pl.exceptions.ColumnNotFoundError):
                console.print(f"[red]No se encontró una columna:[/] {detalle}")
                raise typer.Exit(2) from exc
            console.print(
                f"[red]Error inesperado ({type(exc).__name__}):[/] {detalle}\n"
                "[dim]Es un defecto de Vigía, no del dataset. Con VIGIA_DEBUG=1 se ve el "
                "traceback completo.[/]"
            )
            raise typer.Exit(EXIT_INTERNAL_ERROR) from exc

    return wrapper


@app.command()
@_guarded
def audit(
    path: Annotated[
        Path,
        typer.Argument(
            help="Archivo o carpeta con el dataset "
            "(CSV, Parquet, log de Zeek, EVE de Suricata o PCAP)."
        ),
    ],
    label_col: Annotated[
        str | None, typer.Option("--label-col", help="Columna de etiqueta.")
    ] = None,
    split_col: Annotated[
        str | None, typer.Option("--split-col", help="Columna de split (train/test).")
    ] = None,
    time_col: Annotated[
        str | None, typer.Option("--time-col", help="Columna de marca de tiempo.")
    ] = None,
    src_ip_col: Annotated[str | None, typer.Option("--src-ip-col")] = None,
    dst_ip_col: Annotated[str | None, typer.Option("--dst-ip-col")] = None,
    time_format: Annotated[
        str | None,
        typer.Option(
            "--time-format",
            help="Formato de la columna de tiempo (ej. '%m/%d/%Y %H:%M:%S'), para cuando "
            "día y mes son ambiguos.",
        ),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Perfil de un dataset conocido (ej. 'cic-ids-2017'). Un --*-col explícito "
            "siempre gana sobre el perfil.",
        ),
    ] = None,
    event_type: Annotated[
        str,
        typer.Option(
            "--event-type",
            help="Solo para EVE de Suricata: qué tipo de evento auditar (flow, alert…).",
        ),
    ] = "flow",
    checks: Annotated[
        str, typer.Option("--checks", help="'all', ids o categorías separadas por coma.")
    ] = "all",
    report_dir: Annotated[
        Path | None,
        typer.Option("--report", help="Carpeta donde escribir report.html y report.json."),
    ] = None,
    seed: Annotated[int, typer.Option("--seed", help="Semilla, para reproducibilidad.")] = 42,
    shortcut_threshold: Annotated[
        float,
        typer.Option("--shortcut-threshold", help="Umbral de exactitud para marcar un atajo."),
    ] = 0.95,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on", help="Salir con código 1 si hay hallazgos de esta severidad o peor."
        ),
    ] = None,
    streaming: Annotated[
        bool,
        typer.Option(
            "--streaming",
            help=(
                "Para datasets que no entran en memoria. Solo CSV o Parquet, y solo "
                "corre los checks de duplicados y validez; el resto queda listado en "
                "'checks no ejecutados' en vez de saltarse en silencio."
            ),
        ),
    ] = False,
) -> None:
    """Audita un dataset y genera el reporte de hallazgos."""
    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        console.print(
            f"[red]--fail-on inválido: {fail_on!r}. Use uno de: {', '.join(SEVERITY_ORDER)}[/]"
        )
        raise typer.Exit(2)

    if streaming:
        from vigia.core.streaming import run_streaming_audit

        try:
            with console.status(f"Leyendo {path} en modo streaming…"):
                report = run_streaming_audit(
                    path,
                    label_col=label_col,
                    split_col=split_col,
                    time_col=time_col,
                    src_ip_col=src_ip_col,
                    dst_ip_col=dst_ip_col,
                    version=vigia.__version__,
                    seed=seed,
                    profile=profile,
                )
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]No se pudo leer el dataset:[/] {exc}")
            raise typer.Exit(2) from exc
        except ProfileNotFound as exc:
            console.print(f"[red]--profile inválido:[/] {exc}")
            raise typer.Exit(2) from exc

        _print_summary(report)

        if report_dir is not None:
            html_path, json_path = write_report(report, report_dir)
            console.print()
            console.print(f"Reporte HTML: [link=file://{html_path.resolve()}]{html_path}[/]")
            console.print(f"Reporte JSON: {json_path}")

        if fail_on is not None and report.exceeds(fail_on):  # type: ignore[arg-type]
            console.print(f"\n[red]Hay hallazgos de severidad '{fail_on}' o peor.[/]")
            raise typer.Exit(1)
        _exit_if_errors(report)
        return

    try:
        with console.status(f"Leyendo {path}…"):
            ctx = vigia.load(
                path,
                label_col=label_col,
                split_col=split_col,
                time_col=time_col,
                src_ip_col=src_ip_col,
                dst_ip_col=dst_ip_col,
                profile=profile,
                seed=seed,
                event_type=event_type,
                shortcut_threshold=shortcut_threshold,
                time_format=time_format,
            )
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]No se pudo leer el dataset:[/] {exc}")
        raise typer.Exit(2) from exc
    except ProfileNotFound as exc:
        console.print(f"[red]--profile inválido:[/] {exc}")
        raise typer.Exit(2) from exc

    detected = {
        "etiqueta": ctx.label_col,
        "split": ctx.split_col,
        "tiempo": ctx.time_col,
        "src_ip": ctx.src_ip_col,
        "dst_ip": ctx.dst_ip_col,
    }
    console.print(
        "[dim]Columnas: " + ", ".join(f"{k}={v or '—'}" for k, v in detected.items()) + "[/]"
    )

    known_issues = ctx.config.get("profile", {}).get("known_issues") if profile else None
    if known_issues:
        console.print(
            f"[dim]Perfil '{profile}': {len(known_issues)} error(es) conocido(s) de este "
            "dataset — ver el reporte.[/]"
        )

    try:
        with console.status("Ejecutando checks…"):
            report = vigia.audit(ctx, checks=checks)
    except KeyError as exc:
        # `select` rechaza un id o categoría que no existe. Es un error de uso,
        # no un fallo del programa: sin esto salía un traceback con código 1.
        console.print(f"[red]--checks inválido:[/] {exc.args[0]}")
        raise typer.Exit(2) from exc

    _print_summary(report)

    if report_dir is not None:
        html_path, json_path = write_report(report, report_dir)
        console.print()
        console.print(f"Reporte HTML: [link=file://{html_path.resolve()}]{html_path}[/]")
        console.print(f"Reporte JSON: {json_path}")

    if fail_on is not None and report.exceeds(fail_on):  # type: ignore[arg-type]
        console.print(f"\n[red]Hay hallazgos de severidad '{fail_on}' o peor.[/]")
        raise typer.Exit(1)
    _exit_if_errors(report)


@app.command()
@_guarded
def fix(
    path: Annotated[Path, typer.Argument(help="Archivo o carpeta con el dataset.")],
    fixes: Annotated[
        str, typer.Option("--apply", help="Correcciones a aplicar, separadas por coma.")
    ],
    out: Annotated[Path, typer.Option("--out", help="Dónde escribir el dataset corregido.")],
    label_col: Annotated[str | None, typer.Option("--label-col")] = None,
    split_col: Annotated[str | None, typer.Option("--split-col")] = None,
    time_col: Annotated[str | None, typer.Option("--time-col")] = None,
    src_ip_col: Annotated[str | None, typer.Option("--src-ip-col")] = None,
    dst_ip_col: Annotated[str | None, typer.Option("--dst-ip-col")] = None,
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Perfil de un dataset conocido, el mismo que se uso en `vigia audit`.",
        ),
    ] = None,
    time_format: Annotated[
        str | None,
        typer.Option("--time-format", help="Formato de la columna de tiempo (temporal_split)."),
    ] = None,
    seed: Annotated[int, typer.Option("--seed")] = 42,
) -> None:
    """Aplica correcciones a un dataset y escribe el resultado.

    El archivo original nunca se modifica. Las filas con etiqueta dudosa no se
    borran: quedan en un archivo aparte para revisión humana.
    """
    from vigia.fixes import apply_fix, available_fixes
    from vigia.fixes.base import FixNotApplicable

    pedidas = [f.strip() for f in fixes.split(",") if f.strip()]
    desconocidas = [f for f in pedidas if f not in available_fixes()]
    if desconocidas:
        console.print(
            f"[red]Corrección desconocida:[/] {', '.join(desconocidas)}. "
            f"Disponibles: {', '.join(available_fixes())}"
        )
        raise typer.Exit(2)

    # Con `--out` igual a la entrada se leía todo y se pisaba el original, que
    # esta herramienta promete no tocar nunca (AUDITORIA-1.0.md, COR-16).
    # `resolve` iguala rutas relativas, con `.` y enlaces. Una carpeta de entrada
    # no se puede pisar con un archivo, pero tampoco sirve de salida.
    if out.resolve() == path.resolve():
        console.print(
            "[red]--out no puede ser el archivo de entrada:[/] el original nunca se toca. "
            "Elegí otro nombre o carpeta."
        )
        raise typer.Exit(2)

    try:
        ctx = vigia.load(
            path,
            label_col=label_col,
            split_col=split_col,
            time_col=time_col,
            src_ip_col=src_ip_col,
            dst_ip_col=dst_ip_col,
            profile=profile,
            seed=seed,
            time_format=time_format,
        )
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]No se pudo leer el dataset:[/] {exc}")
        raise typer.Exit(2) from exc
    except ProfileNotFound as exc:
        console.print(f"[red]--profile inválido:[/] {exc}")
        raise typer.Exit(2) from exc

    df = ctx.df
    aplicadas = 0
    for fix_id in pedidas:
        # Cada corrección parte del resultado de la anterior, con los mismos
        # roles declarados (ver `AuditContext.with_df`).
        try:
            result = apply_fix(ctx.with_df(df), fix_id)
        except FixNotApplicable as exc:
            console.print(f"[yellow]{fix_id}:[/] no se aplicó — {exc}")
            continue

        df = result.df
        aplicadas += 1
        console.print(f"[green]{fix_id}:[/] {result.summary}")

        if result.quarantined is not None and result.quarantined.height:
            q_path = out.parent / f"{out.stem}_cuarentena{out.suffix}"
            q_path.parent.mkdir(parents=True, exist_ok=True)
            _write(result.quarantined, q_path)
            console.print(f"  [dim]filas apartadas para revisión: {q_path}[/]")

    if not aplicadas:
        console.print("[yellow]Ninguna corrección se pudo aplicar; no se escribió nada.[/]")
        # 1 es "hay hallazgos que alcanzan --fail-on"; esto es un error de uso.
        raise typer.Exit(2)

    out.parent.mkdir(parents=True, exist_ok=True)
    _write(df, out)
    # Sin flechas ni otros caracteres fuera de Latin-1: la consola de Windows
    # usa cp1252 por defecto y un carácter que no puede codificar hace fallar
    # el comando entero después de haber hecho todo el trabajo.
    console.print(
        f"\nDataset corregido: {out}  "
        f"[dim]({ctx.n_rows:,} a {df.height:,} filas, "
        f"{ctx.n_cols} a {df.width} columnas)[/]"
    )


def _write(df: pl.DataFrame, path: Path) -> None:
    """Escribe según la extensión: Parquet conserva los tipos, CSV no."""
    if path.suffix.lower() in (".parquet", ".pq"):
        df.write_parquet(path)
    else:
        df.write_csv(path)


@app.command()
@_guarded
def poison(
    path: Annotated[Path, typer.Argument(help="Archivo o carpeta con el dataset.")],
    label_col: Annotated[str | None, typer.Option("--label-col")] = None,
    top: Annotated[int, typer.Option("--top", help="Cuántas filas sospechosas listar.")] = 20,
    min_detectors: Annotated[
        int,
        typer.Option(
            "--min-detectors",
            help="Solo filas señaladas por al menos esta cantidad de detectores.",
        ),
    ] = 2,
    report_dir: Annotated[Path | None, typer.Option("--report")] = None,
    seed: Annotated[int, typer.Option("--seed")] = 42,
) -> None:
    """Busca registros insertados a propósito para manipular el modelo.

    Ningún detector basta solo, así que por defecto solo se listan las filas
    que al menos dos señalan por motivos distintos. Con `--min-detectors 1` se
    ve todo, a costa de muchos más falsos positivos.
    """
    from vigia.core.engine import run_audit
    from vigia.poison import rank_suspects

    try:
        with console.status(f"Leyendo {path}…"):
            ctx = vigia.load(path, label_col=label_col, seed=seed)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]No se pudo leer el dataset:[/] {exc}")
        raise typer.Exit(2) from exc

    with console.status("Ejecutando detectores…"):
        report = run_audit(ctx, version=vigia.__version__, module="poison")

    _print_summary(report)

    sospechosas = rank_suspects(report.findings, top=top, min_detectors=min_detectors)
    if sospechosas:
        console.print(
            f"\n[bold]Filas más sospechosas[/] [dim](señaladas por {min_detectors}+ detectores)[/]"
        )
        table = Table(show_header=True, header_style="dim", box=None, padding=(0, 2, 0, 0))
        table.add_column("Fila", justify="right")
        table.add_column("Puntaje", justify="right")
        table.add_column("Detectores")
        for s in sospechosas:
            table.add_row(f"{s.row:,}", f"{s.score:.3f}", ", ".join(s.detectors))
        console.print(table)
        console.print(
            "\n[dim]Un puntaje alto es motivo para revisar la fila, no un "
            "veredicto. Revisar a mano antes de borrar nada.[/]"
        )
    elif report.findings:
        console.print(
            f"\n[dim]Ningún registro fue señalado por {min_detectors}+ detectores. "
            "Con --min-detectors 1 se ven todos los hallazgos individuales.[/]"
        )

    if report_dir is not None:
        html_path, json_path = write_report(report, report_dir)
        console.print(f"\nReporte HTML: {html_path}")
        console.print(f"Reporte JSON: {json_path}")

    _exit_if_errors(report)


@app.command()
@_guarded
def drift(
    path: Annotated[Path, typer.Argument(help="Lote nuevo a evaluar.")],
    reference: Annotated[
        Path,
        typer.Option("--reference", help="Dataset de referencia (con el que se entrenó)."),
    ],
    label_col: Annotated[str | None, typer.Option("--label-col")] = None,
    psi_threshold: Annotated[
        float, typer.Option("--psi-threshold", help="PSI a partir del cual reportar.")
    ] = 0.2,
    report_dir: Annotated[Path | None, typer.Option("--report")] = None,
    seed: Annotated[int, typer.Option("--seed")] = 42,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Salir con código 1 si hay deriva de este nivel o peor."),
    ] = None,
) -> None:
    """Compara un lote nuevo contra la referencia y reporta la deriva.

    La deriva no es un defecto del dataset: puede estar perfecto y aun así
    haber cambiado la red. Lo que indica es que conviene reentrenar.
    """
    from vigia.core.engine import run_audit
    from vigia.io.readers import read_dataset, strip_column_names

    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        console.print(f"[red]--fail-on inválido: {fail_on!r}[/]")
        raise typer.Exit(2)

    try:
        with console.status("Leyendo…"):
            ctx = vigia.load(path, label_col=label_col, seed=seed, psi_threshold=psi_threshold)
            ctx.reference = strip_column_names(read_dataset(reference))
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]No se pudo leer el dataset:[/] {exc}")
        raise typer.Exit(2) from exc

    console.print(
        f"[dim]Referencia: {ctx.reference.height:,} filas · Lote actual: {ctx.n_rows:,} filas[/]"
    )

    with console.status("Comparando distribuciones…"):
        report = run_audit(ctx, version=vigia.__version__, module="drift")

    _print_summary(report)

    # Solo si todo corrió: un check saltado o roto no dice "no hay deriva".
    if not report.findings and not report.skipped and not report.errors:
        console.print("\n[green]El lote se parece a la referencia: no hace falta reentrenar.[/]")

    if report_dir is not None:
        html_path, json_path = write_report(report, report_dir)
        console.print(f"\nReporte HTML: {html_path}")
        console.print(f"Reporte JSON: {json_path}")

    if fail_on is not None and report.exceeds(fail_on):  # type: ignore[arg-type]
        console.print(f"\n[red]Hay deriva de nivel '{fail_on}' o peor.[/]")
        raise typer.Exit(1)
    _exit_if_errors(report)


@app.command(name="fixes")
def list_fixes() -> None:
    """Lista las correcciones automáticas disponibles."""
    from vigia.fixes import available_fixes
    from vigia.fixes.base import get_fix

    table = Table(show_header=True, header_style="dim", box=None, padding=(0, 2, 0, 0))
    table.add_column("ID")
    table.add_column("Qué hace")
    for fix_id in available_fixes():
        doc = (get_fix(fix_id).__doc__ or "").strip().split("\n")[0]
        table.add_row(f"[cyan]{fix_id}[/]", doc)
    console.print(table)


@app.command(name="checks")
def list_checks(
    module: Annotated[
        str,
        typer.Option("--module", help="auditor, poison, drift, o 'all' para todos."),
    ] = "auditor",
) -> None:
    """Lista los checks disponibles."""
    from vigia.core.registry import module_of

    seleccion = all_checks(None if module == "all" else module)  # type: ignore[arg-type]
    if not seleccion:
        console.print(f"[yellow]No hay checks en el módulo {module!r}.[/]")
        raise typer.Exit(2)

    todos = module == "all"
    table = Table(show_header=True, header_style="dim", box=None, padding=(0, 2, 0, 0))
    table.add_column("ID")
    table.add_column("Categoría")
    table.add_column("Nombre")
    if todos:
        table.add_column("Módulo")

    def fila(cid: str, categoria: str, nombre: str, mod: str) -> None:
        cols = [f"[cyan]{cid}[/]", f"[dim]{categoria}[/]", nombre]
        if todos:
            cols.append(f"[dim]{mod}[/]")
        table.add_row(*cols)

    for c in seleccion:
        mod = module_of(c)
        fila(c.id, c.category, c.name, mod)
        # Los ids secundarios se listan bajo el check que los emite: aparecen en
        # el reporte, así que tienen que figurar en el catálogo.
        for extra in getattr(c, "also_emits", ()):
            fila(extra, c.category, f"-> vía {c.id}", mod)
    console.print(table)


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Interfaz donde escuchar.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Puerto.")] = 8000,
    reload: Annotated[
        bool, typer.Option("--reload", help="Recargar al detectar cambios (para desarrollo).")
    ] = False,
) -> None:
    r"""Levanta la API REST (requiere `pip install 'vigia-nids\[api]'`)."""
    try:
        import uvicorn
    except ImportError as exc:
        console.print(
            r"[red]Falta el extra 'api':[/] instalá con [bold]pip install 'vigia-nids\[api]'[/]"
        )
        raise typer.Exit(2) from exc

    uvicorn.run("vigia.api.app:app", host=host, port=port, reload=reload)


@app.command()
def version() -> None:
    """Muestra la versión de Vigía."""
    console.print(vigia.__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
