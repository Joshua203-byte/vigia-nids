"""Reporte HTML autocontenido (requisito R8, estructura de la sección 15.1).

Sin Jinja2 por ahora: una plantilla en f-strings basta para el MVP y evita una
dependencia más. Cuando el reporte crezca (gráficos Plotly, sección 15) se
migra a Jinja2 como indica la sección 12.4.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path

from vigia.core.findings import Report

_SEVERITY_COLOR = {
    "critical": "#b3122c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#3f6212",
    "info": "#1f5673",
}

_LIGHT_COLOR = {
    "rojo": "#b3122c",
    "amarillo": "#a16207",
    "verde": "#3f6212",
    "gris": "#57534e",
}

_CSS = """
:root { color-scheme: light dark; --bg:#fbfbfa; --fg:#1a1a18; --card:#fff; --line:#e3e3df; --muted:#5c5c56; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16161a; --fg:#ececea; --card:#1e1e24; --line:#32323a; --muted:#a0a09a; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif; }
.wrap { max-width: 980px; margin:0 auto; padding: 32px 16px 64px; }
h1 { font-size:1.8rem; margin:0 0 4px; letter-spacing:-.02em; }
h2 { font-size:1.15rem; margin:36px 0 12px; }
.sub { color:var(--muted); margin:0 0 24px; }
.light { display:inline-block; padding:6px 14px; border-radius:999px; color:#fff; font-weight:600; font-size:.85rem; text-transform:uppercase; letter-spacing:.06em; }
.counts { display:flex; flex-wrap:wrap; gap:8px; margin:16px 0 0; padding:0; list-style:none; }
.counts li { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:8px 14px; font-size:.85rem; }
.counts b { font-size:1.2rem; display:block; }
.meta { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; font-size:.87rem; }
.meta dl { display:grid; grid-template-columns:auto 1fr; gap:4px 16px; margin:0; }
.meta dt { color:var(--muted); }
.meta dd { margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
.finding { background:var(--card); border:1px solid var(--line); border-left-width:5px; border-radius:10px; padding:16px 18px; margin:14px 0; }
.finding h3 { margin:0 0 6px; font-size:1rem; }
.badge { display:inline-block; padding:2px 9px; border-radius:5px; color:#fff; font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.05em; margin-right:8px; vertical-align:2px; }
.cid { font-family:ui-monospace,monospace; font-size:.78rem; color:var(--muted); }
.rec { border-top:1px dashed var(--line); margin-top:12px; padding-top:10px; font-size:.9rem; }
.rec b { color:var(--muted); font-weight:600; }
table { border-collapse:collapse; width:100%; font-size:.82rem; margin-top:10px; }
th,td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
th { color:var(--muted); font-weight:600; }
.scroll { overflow-x:auto; }
details { margin-top:10px; }
summary { cursor:pointer; color:var(--muted); font-size:.85rem; }
.empty { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:24px; text-align:center; color:var(--muted); }
"""


def _esc(x: object) -> str:
    """Escapa contenido derivado del dataset, comillas incluidas.

    Los nombres de columna y los valores vienen de tráfico de red capturado:
    son entrada no confiable. Hoy todos se interpolan en posición de texto, así
    que `quote=False` bastaría, pero basta con que alguien agregue un `title=`
    o un `data-` para que una comilla se escape del atributo. Escapar siempre
    cuesta nada y quita la posibilidad de raíz.
    """
    return html.escape(str(x), quote=True)


def _examples_table(examples: list[dict]) -> str:
    if not examples:
        return ""
    cols = list(examples[0].keys())
    head = "".join(f"<th>{_esc(c)}</th>" for c in cols)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(row.get(c, ''))}</td>" for c in cols) + "</tr>"
        for row in examples
    )
    return (
        "<details><summary>Ver evidencia "
        f"({len(examples)} ejemplo{'s' if len(examples) != 1 else ''})</summary>"
        f'<div class="scroll"><table><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div></details>"
    )


def _metric_line(metric: dict[str, float]) -> str:
    if not metric:
        return ""
    parts = []
    for k, v in metric.items():
        formatted = f"{v:.4g}" if isinstance(v, (int, float)) else str(v)
        parts.append(f"<code>{_esc(k)}={_esc(formatted)}</code>")
    return '<p class="cid">' + " · ".join(parts) + "</p>"


def render_html(report: Report) -> str:
    counts = report.counts()
    light = report.traffic_light()
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    if report.findings:
        blocks = []
        for f in report.sorted_findings():
            color = _SEVERITY_COLOR[f.severity]
            blocks.append(
                f'<div class="finding" style="border-left-color:{color}">'
                f'<h3><span class="badge" style="background:{color}">{_esc(f.severity)}</span>'
                f"{_esc(f.title)}</h3>"
                f'<p class="cid">{_esc(f.check_id)} · {f.affected_rows:,} filas afectadas</p>'
                f"<p>{_esc(f.description)}</p>"
                f"{_metric_line(f.metric)}"
                f"{_examples_table(f.examples)}"
                f'<div class="rec"><b>Recomendación:</b> {_esc(f.recommendation)}'
                + (
                    f' <span class="cid">(corrección automática: <code>{_esc(f.auto_fix)}</code>)</span>'
                    if f.auto_fix
                    else ""
                )
                + "</div></div>"
            )
        findings_html = "".join(blocks)
    elif report.errors:
        findings_html = (
            f'<div class="empty">Ningún check reportó hallazgos, pero '
            f"<b>{len(report.errors)} fallaron por un error interno</b> (ver abajo). "
            "El reporte está incompleto por un defecto de Vigía, no por el dataset: "
            "no se puede dar por limpio.</div>"
        )
    elif report.skipped:
        findings_html = (
            f'<div class="empty">Ningún check reportó hallazgos, pero '
            f"<b>{len(report.skipped)} no se ejecutaron</b> (ver abajo). El dataset no "
            "quedó revisado del todo: los checks que se saltan suelen ser los que "
            "dependen de la etiqueta o del split, que son los que detectan fuga y "
            "duplicados entre conjuntos.</div>"
        )
    else:
        findings_html = (
            '<div class="empty">Ningún check reportó hallazgos y todos se ejecutaron.</div>'
        )

    skipped_html = ""
    if report.skipped:
        rows = "".join(
            f"<tr><td><code>{_esc(k)}</code></td><td style='white-space:normal'>{_esc(v)}</td></tr>"
            for k, v in sorted(report.skipped.items())
        )
        skipped_html = (
            "<h2>Checks que no se ejecutaron</h2>"
            f'<div class="scroll"><table><thead><tr><th>Check</th><th>Motivo</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
        )

    # Los errores van aparte de los saltos: saltarse es "no aplicaba a este
    # dataset"; fallar es un bug, y mezclarlos hacía que un crash se leyera como
    # una columna que faltaba (AUDITORIA-1.0.md, COR-05).
    errors_html = ""
    if report.errors:
        rows = "".join(
            f"<tr><td><code>{_esc(k)}</code></td><td style='white-space:normal'>{_esc(v)}</td></tr>"
            for k, v in sorted(report.errors.items())
        )
        errors_html = (
            "<h2>Checks que fallaron</h2>"
            '<p class="sub">Fallaron por un error interno de Vigía. Los demás resultados '
            "valen, pero este reporte está incompleto.</p>"
            f'<div class="scroll"><table><thead><tr><th>Check</th><th>Error</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
        )

    counts_html = "".join(
        f"<li>{_esc(sev)}<b>{n}</b></li>" for sev, n in counts.items() if n or sev == "critical"
    )

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigía — reporte de auditoría</title>
<style>{_CSS}</style>
</head>
<body><div class="wrap">
<h1>Reporte de auditoría</h1>
<p class="sub">{_esc(report.dataset_path)} · generado el {generated}</p>
<p><span class="light" style="background:{_LIGHT_COLOR[light]}">{_esc(light)}</span></p>
<ul class="counts">{counts_html}</ul>

<h2>Hallazgos</h2>
{findings_html}

{errors_html}

{skipped_html}

<h2>Anexo técnico</h2>
<div class="meta"><dl>
<dt>Filas</dt><dd>{report.n_rows:,}</dd>
<dt>Columnas</dt><dd>{report.n_cols:,}</dd>
<dt>SHA-256</dt><dd>{_esc(report.dataset_sha256)}</dd>
<dt>Versión de Vigía</dt><dd>{_esc(report.vigia_version)}</dd>
<dt>Semilla</dt><dd>{report.seed}</dd>
</dl></div>
</div></body></html>"""


def write_report(report: Report, out_dir: str | Path) -> tuple[Path, Path]:
    """Escribe ``report.html`` y ``report.json`` en ``out_dir``."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)

    html_path = d / "report.html"
    json_path = d / "report.json"
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return html_path, json_path
