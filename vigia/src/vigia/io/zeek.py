"""Lector de logs de Zeek (R13).

Zeek escribe TSV con una cabecera propia: varias lineas que empiezan con `#`
declaran el separador, los nombres de campo, los tipos y el valor que
representa un vacio. Sin leer esa cabecera el archivo es un TSV sin nombres de
columna y con `-` donde deberia haber nulos.

Desde Zeek 3 tambien existe la salida en JSON Lines, que no lleva cabecera.
Ambas se detectan por contenido, no por nombre: un `conn.log` puede ser
cualquiera de las dos.

Lo que este modulo NO hace es interpretar el contenido. Un `conn.log` trae los
flujos, un `dns.log` las consultas, y decidir que significa cada campo es
trabajo de los checks, no del lector.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import polars as pl

#: Tipos de Zeek que hay que convertir a numero. El resto entra como texto:
#: `addr` y `port` son identificadores, y convertir un puerto a entero invita a
#: que alguien lo promedie.
_NUMERIC_TYPES = frozenset({"count", "int", "double", "interval", "time"})


class ZeekFormatError(ValueError):
    """El archivo no parece un log de Zeek."""


def _parse_header(lines: list[str]) -> dict[str, Any]:
    """Lee las directivas `#campo valor` del encabezado TSV."""
    meta: dict[str, Any] = {}
    for line in lines:
        if not line.startswith("#"):
            break
        # El separador se declara a si mismo escapado: `#separator \x09`. El
        # valor son los cuatro caracteres literales, asi que hay que
        # desescaparlo, pero no se puede usar `.strip()` antes: si el archivo
        # ya trae el tab real --lo hacen algunas herramientas que reescriben
        # los logs-- el strip lo borraria y quedaria un separador vacio.
        if line.startswith("#separator"):
            valor = line[len("#separator") :].removeprefix(" ").rstrip("\r\n")
            if not valor:
                continue
            if "\\" in valor:
                valor = valor.encode().decode("unicode_escape")
            meta["separator"] = valor
            continue

        sep = meta.get("separator", "\t")
        # `\r\n`, no solo `\n`: un log copiado a Windows deja el retorno de
        # carro pegado al ultimo campo, y la columna pasa a llamarse
        # `orig_bytes\r`, que despues no matchea con nada.
        partes = line[1:].rstrip("\r\n").split(sep)
        if not partes:
            continue
        clave, valores = partes[0], partes[1:]
        if clave in ("fields", "types"):
            meta[clave] = valores
        elif valores:
            meta[clave] = valores[0]
    return meta


def _is_json_lines(head: str) -> bool:
    for line in head.splitlines():
        s = line.strip()
        if s:
            return s.startswith("{")
    return False


def read_zeek(path: str | Path) -> pl.DataFrame:
    """Lee un log de Zeek, en TSV con cabecera o en JSON Lines.

    Los nombres de campo se conservan tal como los escribe Zeek, incluidos los
    puntos (`id.orig_h`). La deteccion de columnas ya los reconoce.
    """
    p = Path(path)
    raw = p.read_bytes()
    # Zeek escribe UTF-8, pero un payload capturado puede traer cualquier byte
    # en un campo de texto y no hay razon para perder el archivo entero por eso.
    text = raw.decode("utf-8", errors="replace")
    # Los CRLF se normalizan una sola vez, aca. Con separador tab explicito el
    # `\r` no es delimitador, asi que se quedaria pegado al ultimo valor de
    # cada fila y a la ultima columna de `#fields`.
    text = text.replace("\r\n", "\n")

    if _is_json_lines(text[:4096]):
        return pl.read_ndjson(io.StringIO(text))

    lines = text.splitlines(keepends=True)
    meta = _parse_header(lines)
    campos = meta.get("fields")
    if not campos:
        raise ZeekFormatError(
            f"{p.name}: no es JSON Lines ni tiene cabecera '#fields'. "
            "Si es un TSV sin cabecera, hay que darle nombres de columna."
        )

    sep = meta.get("separator", "\t")
    unset = meta.get("unset_field", "-")
    empty = meta.get("empty_field", "(empty)")

    # El cuerpo son las lineas que no son directivas. `#close` va al final, asi
    # que filtrar por el prefijo es mas seguro que contar lineas de cabecera.
    cuerpo = "".join(ln for ln in lines if not ln.startswith("#"))
    if not cuerpo.strip():
        return pl.DataFrame({c: [] for c in campos})

    df = pl.read_csv(
        io.StringIO(cuerpo),
        separator=sep,
        has_header=False,
        new_columns=campos,
        null_values=[unset, empty],
        infer_schema_length=10_000,
        truncate_ragged_lines=True,
    )

    tipos = meta.get("types")
    if tipos and len(tipos) == len(campos):
        df = _cast_types(df, campos, tipos)
    return df


def _cast_types(df: pl.DataFrame, campos: list[str], tipos: list[str]) -> pl.DataFrame:
    """Convierte segun los tipos que declara Zeek.

    `strict=False` a proposito: un campo corrupto en una captura real es comun,
    y perder esa fila entera es peor que dejarla con un nulo. El check de
    validez lo reporta despues.
    """
    casts = []
    for campo, tipo in zip(campos, tipos, strict=True):
        if campo not in df.columns or tipo not in _NUMERIC_TYPES:
            continue
        destino = pl.Int64 if tipo in ("count", "int") else pl.Float64
        if df.schema[campo] != destino:
            casts.append(pl.col(campo).cast(destino, strict=False))
    return df.with_columns(casts) if casts else df
