"""Lectores de datasets (R1, R13, R14) y detección de columnas clave.

CSV y Parquet, archivo suelto o carpeta (los datasets CIC vienen partidos en un
CSV por día), más logs de Zeek, Suricata EVE y capturas PCAP.

El formato se decide por extensión, salvo dos casos que necesitan mirar el
contenido: un `.log` puede ser TSV de Zeek o JSON Lines, y un `.json` puede ser
EVE de Suricata o un JSON cualquiera.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import polars as pl

#: `.binetflow` (y `.2format`, como se publican los de CTU-13) son CSV con otra extension.
CSV_SUFFIXES = {".csv", ".txt", ".binetflow", ".2format"}
PARQUET_SUFFIXES = {".parquet", ".pq"}
ZEEK_SUFFIXES = {".log"}
SURICATA_SUFFIXES = {".json", ".eve"}
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}

#: Todo lo que `read_dataset` acepta al recorrer una carpeta. Los PCAP quedan
#: fuera a propósito: extraer flujos de una captura tarda minutos, y hacerlo
#: para cada archivo de una carpeta sin que nadie lo pidiera sería una sorpresa
#: cara. Un PCAP suelto sí se lee.
READABLE_SUFFIXES = CSV_SUFFIXES | PARQUET_SUFFIXES | ZEEK_SUFFIXES | SURICATA_SUFFIXES

#: Nombres frecuentes por rol, en minúsculas y sin espacios ni signos.
_CANDIDATES: dict[str, tuple[str, ...]] = {
    # `alertsignature` y `alertcategory` son de Suricata: en un EVE de alertas
    # la firma que disparó es lo más parecido a una etiqueta que hay.
    "label": (
        "label",
        "labels",
        "class",
        "attack",
        "attackcat",
        "attackcategory",
        "target",
        "alertsignature",
        "alertcategory",
    ),
    "split": ("split", "set", "subset", "partition", "fold"),
    "time": ("timestamp", "ts", "tsstart", "starttime", "flowstart", "datetime", "date", "time"),
    "src_ip": ("srcip", "sourceip", "sourceipaddress", "ipsrc", "sa", "idorigh"),
    "dst_ip": ("dstip", "destinationip", "destip", "ipdst", "da", "idresph"),
    "src_port": ("srcport", "sourceport", "portsrc", "sport", "sp", "idorigp"),
    "dst_port": ("dstport", "destinationport", "destport", "portdst", "dp", "idrespp"),
    "protocol": ("protocol", "proto", "protocoltype", "ipproto"),
}

#: Candidatos demasiado cortos para buscarlos como subcadena: 'ts' aparece
#: dentro de 'pkts_fwd', 'da' dentro de 'date', 'sport' dentro de 'dsport'
#: (UNSW-NB15, donde sería el puerto de destino). Solo coincidencia exacta.
_EXACT_ONLY = frozenset(
    {"ts", "sa", "da", "id", "set", "date", "time", "class", "sp", "dp", "proto", "sport"}
)


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def detect_column(df: pl.DataFrame, role: str) -> str | None:
    """Busca la columna que cumple ``role`` ('label', 'time', 'src_ip'…).

    Primero intenta coincidencia exacta del nombre normalizado sobre todos los
    candidatos; luego, solo para los candidatos suficientemente específicos,
    acepta que el nombre de la columna los contenga. Devuelve ``None`` si no
    encuentra nada: los checks que dependan de esa columna se saltarán y lo
    dirán en el reporte, que es preferible a correr sobre la columna equivocada.
    """
    candidates = _CANDIDATES.get(role, ())
    normalized = {c: _normalize(c) for c in df.columns}

    for cand in candidates:
        for col, norm in normalized.items():
            if norm == cand:
                return col
    for cand in candidates:
        if cand in _EXACT_ONLY:
            continue
        for col, norm in normalized.items():
            if cand in norm:
                return col
    return None


#: Solo el vacío es nulo. `Infinity`, `-Infinity` y `NaN` estaban acá y los
#: infinitos de CICFlowMeter (Java los escribe así) se leían como nulos:
#: `validity.nan_inf` los reportaba como "low, 0 infinitos" en vez de "high"
#: (AUDITORIA-1.0.md, SCI-07). El parser Float64 de Polars los acepta tal cual;
#: ver `promoted_int_overrides` para las columnas que la inferencia deja en texto.
_CSV_NULL_VALUES = [""]

#: Mas alla de 2**53 un entero ya no cabe exacto en un Float64.
_MAX_EXACT_FLOAT_INT = 2**53


def csv_options(columns: list[str] | None = None) -> dict[str, object]:
    """Opciones comunes de lectura de CSV (eager y streaming).

    Con ``columns`` el archivo se trata como un CSV **sin cabecera** y esos son
    los nombres de sus columnas (UGR'16 se publica así; ver el perfil).
    """
    opts: dict[str, object] = {
        "infer_schema_length": 10_000,
        "ignore_errors": True,
        "null_values": _CSV_NULL_VALUES,
    }
    if columns is not None:
        opts["has_header"] = False
        opts["new_columns"] = columns
    return opts


def promoted_int_overrides(source: object, opts: dict[str, object]) -> dict[str, pl.DataType]:
    """Columnas inferidas como enteros o como texto numérico, para leerlas como ``Float64``.

    El tipo se infiere con las primeras 10.000 filas. Si una columna parece
    entera ahí pero más adelante trae decimales (``1249`` al principio y
    ``150.0`` después, como en CSE-CIC-IDS2018), ``ignore_errors=True`` convierte
    esos valores en nulos **sin avisar**, y los checks de validez los reportan
    como datos corruptos que nunca existieron. Un ``Float64`` lee ambos.

    Lo mismo pasa con ``Infinity`` y ``NaN``: si aparecen dentro de la ventana,
    la inferencia deja la columna entera como texto, y fuera de ella se volvían
    nulos. Una columna de texto en la que **todos** los valores no nulos se leen
    como número es una columna numérica con esos tokens: se fuerza a ``Float64``,
    que los lee como infinito y NaN reales. Una de texto de verdad (una
    etiqueta) tiene valores que no son número y queda como está.
    """
    head = pl.read_csv(source, n_rows=10_000, **opts)  # type: ignore[arg-type]
    out: dict[str, pl.DataType] = {}
    for c, t in head.schema.items():
        if t.is_integer():
            out[c] = pl.Float64()
        elif t == pl.String:
            valores = head.get_column(c).drop_nulls()
            if valores.len() and valores.cast(pl.Float64, strict=False).null_count() == 0:
                out[c] = pl.Float64()
    return out


def _restore_integers(df: pl.DataFrame, promoted: dict[str, pl.DataType]) -> pl.DataFrame:
    """Devuelve a entero las columnas promovidas cuyos valores son todos enteros."""
    fixes = []
    for col in promoted:
        s = df.get_column(col).drop_nulls()
        if s.is_empty() or (
            s.abs().max() < _MAX_EXACT_FLOAT_INT  # type: ignore[operator]
            and (s == s.floor()).all()
        ):
            fixes.append(pl.col(col).cast(pl.Int64))
    return df.with_columns(fixes) if fixes else df


#: Bytes que se decodifican como Windows-1252 al leer una muestra: alcanza para
#: las primeras filas sin traer el archivo entero a memoria.
_SAMPLE_BYTES = 8 * 1024 * 1024


def _read_csv(
    path: Path, columns: list[str] | None = None, n_rows: int | None = None
) -> pl.DataFrame:
    """Lee un CSV tolerando codificaciones que no son UTF-8.

    Con ``n_rows`` lee solo esa cantidad de filas (una muestra): la API valida
    las subidas asi, con el mismo lector que la auditoria, sin cargar el
    archivo entero (AUDITORIA-1.0.md, SEC-04 y COR-06).

    CIC-IDS2017 etiqueta los ataques web como ``Web Attack \x96 Brute Force``,
    con un guion largo en Windows-1252. Polars rechaza el archivo entero por
    ese byte, así que sin este arreglo el día de ataques web —uno de los ocho—
    es simplemente imposible de auditar.
    """
    opts = csv_options(columns)

    def read(source: object) -> pl.DataFrame:
        promoted = promoted_int_overrides(source, opts)
        df = pl.read_csv(source, schema_overrides=promoted, n_rows=n_rows, **opts)  # type: ignore[arg-type]
        return _restore_integers(df, promoted)

    try:
        return read(path)
    except pl.exceptions.ComputeError as exc:
        if "utf-8" not in str(exc).lower():
            raise
    # Se relee entero y se transcodifica en memoria. Windows-1252 acepta
    # cualquier byte, así que no puede volver a fallar por codificación.
    if n_rows is None:
        raw = path.read_bytes()
    else:
        with path.open("rb") as handle:
            raw = handle.read(_SAMPLE_BYTES)
    return read(io.BytesIO(raw.decode("cp1252").encode("utf-8")))


def read_csv_sample(path: Path, n_rows: int = 10_000) -> pl.DataFrame:
    """Primeras ``n_rows`` filas de un CSV, con el mismo lector que la auditoria."""
    return _read_csv(path, n_rows=n_rows)


def _read_json_lines(path: Path, event_type: str | None = "flow") -> pl.DataFrame:
    """Distingue un EVE de Suricata de un JSON Lines cualquiera.

    La diferencia está en el contenido, no en el nombre: los dos se llaman
    `.json`. Un EVE trae `event_type` en cada objeto, y leerlo sin filtrar por
    ese campo mezcla alertas con flujos y produce un DataFrame mayormente nulo.
    """
    from vigia.io.suricata import SuricataFormatError, read_suricata

    try:
        return read_suricata(path, event_type=event_type)
    except SuricataFormatError as exc:
        # Sin `event_type` no es un EVE; se lee como JSON Lines normal. Pero si
        # es un EVE sin eventos del tipo pedido, el mensaje ya dice cuáles hay
        # y perderlo detrás de un error genérico no ayudaría a nadie.
        if "event_type" not in str(exc):
            raise
        return pl.read_ndjson(path)


def _read_one(
    path: Path, event_type: str | None = "flow", csv_columns: list[str] | None = None
) -> pl.DataFrame:
    suffix = path.suffix.lower()
    if suffix in PARQUET_SUFFIXES:
        return pl.read_parquet(path)
    if suffix in CSV_SUFFIXES:
        return _read_csv(path, csv_columns)
    if suffix in ZEEK_SUFFIXES:
        from vigia.io.zeek import read_zeek

        return read_zeek(path)
    if suffix in SURICATA_SUFFIXES:
        return _read_json_lines(path, event_type)
    if suffix in PCAP_SUFFIXES:
        from vigia.io.pcap import read_pcap

        return read_pcap(path)
    raise ValueError(
        f"formato no soportado: {path.suffix!r} ({path}). "
        f"Se aceptan: {', '.join(sorted(READABLE_SUFFIXES | PCAP_SUFFIXES))}"
    )


def read_dataset(
    path: str | Path,
    *,
    event_type: str | None = "flow",
    csv_columns: list[str] | None = None,
) -> pl.DataFrame:
    """Lee un archivo o una carpeta de archivos y los concatena.

    Al concatenar una carpeta se agrega la columna ``__source_file`` para no
    perder la procedencia de cada fila.

    ``event_type`` solo aplica a los EVE de Suricata, que mezclan tipos de
    evento en el mismo archivo. Los flujos son el equivalente a una fila de
    CICFlowMeter, pero las alertas son las que traen algo parecido a una
    etiqueta, así que cuál interesa depende de qué se quiera auditar.

    ``csv_columns`` solo aplica a los CSV: si se pasa, se leen sin cabecera y
    con esos nombres de columna.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"no existe: {p}")

    if p.is_file():
        return _read_one(p, event_type, csv_columns)

    files = sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in READABLE_SUFFIXES)
    if not files:
        pcaps = [f for f in p.rglob("*") if f.suffix.lower() in PCAP_SUFFIXES]
        if pcaps:
            raise FileNotFoundError(
                f"la carpeta {p} solo contiene PCAP. Extraer flujos tarda minutos "
                f"por archivo, así que hay que indicar uno concreto: {pcaps[0]}"
            )
        raise FileNotFoundError(
            f"la carpeta {p} no contiene ningún archivo legible "
            f"({', '.join(sorted(READABLE_SUFFIXES))})"
        )

    frames = [
        _read_one(f, event_type, csv_columns).with_columns(pl.lit(f.name).alias("__source_file"))
        for f in files
    ]
    return pl.concat(frames, how="diagonal_relaxed")


def strip_column_names(df: pl.DataFrame) -> pl.DataFrame:
    """Quita espacios sobrantes de los nombres de columna.

    Los CSV de CIC-IDS2017 traen nombres como ``" Destination Port"``. Lo
    reportamos aparte como hallazgo de higiene, pero para trabajar conviene
    normalizarlos.
    """
    return df.rename({c: c.strip() for c in df.columns})
