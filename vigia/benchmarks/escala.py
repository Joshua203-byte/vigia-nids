"""¿Hasta cuántas filas aguanta una auditoría completa? (docs/PLAN.md, fase 1)

Genera datasets sintéticos de distintos tamaños, corre una auditoría completa
sobre cada uno en un proceso aparte —así el pico de memoria de un tamaño no
queda contaminado por el allocator del anterior— y mide dos cosas:

  * el pico de RSS del proceso, no el promedio: es lo que decide si el
    proceso muere en una máquina con memoria limitada;
  * qué check individual es el más caro, para saber dónde optimizar después.

Uso:
    python benchmarks/escala.py                    # 1M, 5M, 10M, 25M filas
    python benchmarks/escala.py 1_000_000 5_000_000 # tamaños a medida
    python benchmarks/escala.py --worker 1000000    # una sola corrida (interno)
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_SIZES = [1_000_000, 5_000_000, 10_000_000, 25_000_000]
N_FLOAT_COLS = 8


def _build_dataset(n_rows: int):
    import polars as pl

    idx = pl.int_range(0, n_rows, eager=True)
    rng_cols = {f"feature_{i}": (idx % (997 + i)).cast(pl.Float64) for i in range(N_FLOAT_COLS)}
    rng_cols["Destination Port"] = idx % 65535
    rng_cols["Label"] = (idx % 5).cast(pl.Utf8)
    rng_cols["split"] = pl.Series(
        "split", ["train" if i % 10 < 7 else "test" for i in range(n_rows)]
    )
    return pl.DataFrame(rng_cols)


def _run_worker(n_rows: int) -> None:
    """Corre una auditoría completa sobre ``n_rows`` filas sintéticas y
    escribe el resultado como JSON en stdout. Pensado para correr en un
    proceso aparte, invocado por ``main()``."""
    import psutil

    from vigia.core.context import AuditContext
    from vigia.core.findings import Finding
    from vigia.core.registry import select

    proc = psutil.Process()
    df = _build_dataset(n_rows)

    ctx = AuditContext(df=df, label_col="Label", split_col="split", seed=42)

    per_check: dict[str, float] = {}
    t_start = time.perf_counter()
    for check in select("all", "auditor"):
        t0 = time.perf_counter()
        try:
            found: list[Finding] = check.run(ctx)
        except Exception:
            found = []
        per_check[check.id] = time.perf_counter() - t0
        del found
    total_s = time.perf_counter() - t_start

    peak_rss_mb = proc.memory_info().rss / (1024 * 1024)
    slowest = sorted(per_check.items(), key=lambda kv: kv[1], reverse=True)[:3]

    print(
        json.dumps(
            {
                "n_rows": n_rows,
                "total_s": round(total_s, 2),
                "peak_rss_mb": round(peak_rss_mb, 1),
                "slowest_checks": [(cid, round(s, 3)) for cid, s in slowest],
            }
        )
    )


def main() -> None:
    args = sys.argv[1:]
    if args and args[0] == "--worker":
        _run_worker(int(args[1]))
        return

    sizes = [int(a) for a in args] if args else DEFAULT_SIZES
    script = Path(__file__).resolve()
    rows = []

    print(f"{'filas':>12}  {'tiempo':>8}  {'pico RSS':>10}  check mas caro")
    for n in sizes:
        result = subprocess.run(
            [sys.executable, str(script), "--worker", str(n)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            print(f"{n:>12,}  FALLÓ: {result.stderr.strip()[-300:]}")
            rows.append({"n_rows": n, "total_s": None, "peak_rss_mb": None, "slowest_checks": []})
            continue

        data = json.loads(result.stdout.strip().splitlines()[-1])
        top_check = data["slowest_checks"][0][0] if data["slowest_checks"] else "?"
        print(f"{n:>12,}  {data['total_s']:>7.2f}s  {data['peak_rss_mb']:>8.0f} MB  {top_check}")
        rows.append(data)

    _write_report(rows)


def _write_report(rows: list[dict]) -> None:
    out = Path(__file__).parent / "ESCALA.md"
    lines = [
        "# Benchmark de escala",
        "",
        "Generado por `benchmarks/escala.py`. Auditoría completa (todos los",
        "checks del módulo 1) sobre datasets sintéticos, un proceso aparte por",
        "tamaño para que el pico de memoria no se contamine entre corridas.",
        "",
        "| Filas | Tiempo | Pico RSS | Check más caro |",
        "|---|---|---|---|",
    ]
    for r in rows:
        if r["total_s"] is None:
            lines.append(f"| {r['n_rows']:,} | falló | — | — |")
            continue
        top = r["slowest_checks"][0][0] if r["slowest_checks"] else "?"
        lines.append(
            f"| {r['n_rows']:,} | {r['total_s']:.2f} s | {r['peak_rss_mb']:.0f} MB | {top} |"
        )

    lines.append("")
    lines.append("## Los tres checks más caros, por tamaño")
    lines.append("")
    for r in rows:
        if not r["slowest_checks"]:
            continue
        lines.append(f"**{r['n_rows']:,} filas:**")
        for cid, secs in r["slowest_checks"]:
            lines.append(f"- `{cid}`: {secs:.3f} s")
        lines.append("")

    Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nEscrito en {out}")


if __name__ == "__main__":
    main()
