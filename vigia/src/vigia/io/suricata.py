"""Lector de Suricata EVE JSON (R13).

EVE es JSON Lines: un objeto por linea, todos en el mismo archivo pero de
tipos distintos. Un `eve.json` mezcla alertas, flujos, transacciones HTTP y DNS,
y cada `event_type` tiene sus propios campos anidados.

Eso obliga a dos decisiones que este modulo toma explicitamente:

1. **Se filtra por `event_type`.** Mezclar alertas con flujos produce un
   DataFrame donde la mitad de las columnas son nulas en la mitad de las filas,
   y cualquier estadistica sobre el sale mal. Por defecto se leen los flujos,
   que es lo que audita Vigia.

2. **Los objetos anidados se aplanan con guion bajo.** `alert.signature` pasa a
   `alert_signature`. Un DataFrame con structs adentro no se puede hashear ni
   comparar entre splits, que es la mitad de lo que hacen los checks.
"""

from __future__ import annotations

import io
from pathlib import Path

import polars as pl

#: Profundidad maxima al aplanar. Tres niveles cubren `alert.metadata.*`, que es
#: lo mas hondo que trae un EVE normal, sin generar cientos de columnas cuando
#: alguien activa el volcado completo del payload.
MAX_DEPTH = 3


class SuricataFormatError(ValueError):
    """El archivo no parece un EVE JSON de Suricata."""


def _flatten_named(df: pl.DataFrame, depth: int = 0) -> pl.DataFrame:
    """Aplana conservando el nombre del padre: `alert.signature` -> `alert_signature`."""
    if depth >= MAX_DEPTH:
        return df

    structs = [c for c, t in df.schema.items() if isinstance(t, pl.Struct)]
    if not structs:
        return df

    for col in structs:
        campos = df.schema[col].fields  # type: ignore[attr-defined]
        df = df.with_columns(
            [pl.col(col).struct.field(f.name).alias(f"{col}_{f.name}") for f in campos]
        ).drop(col)

    return _flatten_named(df, depth + 1)


def read_suricata(
    path: str | Path,
    *,
    event_type: str | None = "flow",
) -> pl.DataFrame:
    """Lee un `eve.json` y devuelve los eventos de un tipo, aplanados.

    ``event_type=None`` lee todos los tipos, lo cual casi nunca es lo que se
    quiere: el resultado tiene una columna por cada campo de cada tipo de
    evento, la mayoria nula.
    """
    p = Path(path)
    text = p.read_bytes().decode("utf-8", errors="replace")
    if not text.strip():
        raise SuricataFormatError(f"{p.name}: archivo vacio")

    try:
        df = pl.read_ndjson(io.StringIO(text))
    except Exception as exc:
        raise SuricataFormatError(f"{p.name}: no se pudo leer como JSON Lines ({exc})") from exc

    if "event_type" not in df.columns:
        raise SuricataFormatError(
            f"{p.name}: no tiene el campo 'event_type'; no parece un EVE de Suricata"
        )

    if event_type is not None:
        df = df.filter(pl.col("event_type") == event_type)
        if df.is_empty():
            disponibles = (
                pl.read_ndjson(io.StringIO(text)).get_column("event_type").unique().sort().to_list()
            )
            raise SuricataFormatError(
                f"{p.name}: no hay eventos de tipo {event_type!r}. "
                f"Disponibles: {', '.join(str(t) for t in disponibles)}"
            )

    if event_type is not None:
        # Tras filtrar vale lo mismo en todas las filas: una columna constante
        # que `validity.constant` reportaría como defecto del dataset.
        df = df.drop("event_type")

    df = _flatten_named(df)
    # Las columnas que quedaron enteramente nulas vienen de otros tipos de
    # evento y solo estorban.
    vacias = [c for c in df.columns if df.get_column(c).null_count() == df.height]
    return df.drop(vacias) if vacias else df
