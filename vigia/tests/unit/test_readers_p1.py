"""Lectores de Zeek, Suricata EVE y PCAP (R13, R14)."""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl
import pytest

from vigia.io.readers import detect_column, read_dataset
from vigia.io.suricata import SuricataFormatError, read_suricata
from vigia.io.zeek import ZeekFormatError, read_zeek

# --- Zeek ---------------------------------------------------------------------

#: Un `conn.log` real, con la cabecera tal como la escribe Zeek. El separador
#: se declara escapado --los cuatro caracteres literales `\x09`, no un tab-- y
#: los nulos son `-`.
ZEEK_TSV = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#open\t2026-09-19-10-00-00\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\n"
    "1758276000.123\tCabc1\t10.0.0.1\t51234\t93.184.216.34\t443\ttcp\t2.5\t1420\n"
    "1758276001.456\tCabc2\t10.0.0.2\t51235\t93.184.216.34\t80\ttcp\t-\t-\n"
    "#close\t2026-09-19-10-05-00\n"
)


def test_zeek_tsv_lee_la_cabecera(tmp_path: Path):
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_TSV, encoding="utf-8")

    df = read_zeek(p)

    assert df.height == 2, "las lineas '#close' y de cabecera no son datos"
    assert df.columns[:4] == ["ts", "uid", "id.orig_h", "id.orig_p"]
    # Los tipos declarados por Zeek se respetan: `duration` es interval.
    assert df.schema["duration"] == pl.Float64
    assert df.schema["orig_bytes"] == pl.Int64


def test_zeek_convierte_el_unset_field_en_nulo(tmp_path: Path):
    """`-` es el vacío de Zeek, no el texto '-'.

    Sin esto la columna entera queda como texto y ningún check numérico corre.
    """
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_TSV, encoding="utf-8")

    df = read_zeek(p)

    assert df.get_column("duration").null_count() == 1
    assert df.get_column("orig_bytes").to_list() == [1420, None]


def test_zeek_json_lines(tmp_path: Path):
    """Desde Zeek 3 la salida puede ser JSON, sin cabecera."""
    p = tmp_path / "conn.log"
    p.write_text(
        '{"ts":1758276000.1,"uid":"Cabc1","id.orig_h":"10.0.0.1","id.orig_p":51234}\n'
        '{"ts":1758276001.4,"uid":"Cabc2","id.orig_h":"10.0.0.2","id.orig_p":51235}\n',
        encoding="utf-8",
    )

    df = read_zeek(p)

    assert df.height == 2
    assert "id.orig_h" in df.columns


def test_zeek_sin_cabecera_falla_claro(tmp_path: Path):
    """Un TSV pelado no se puede leer: no hay de dónde sacar los nombres."""
    p = tmp_path / "raro.log"
    p.write_text("1758276000\tCabc1\t10.0.0.1\n", encoding="utf-8")

    with pytest.raises(ZeekFormatError, match="#fields"):
        read_zeek(p)


def test_zeek_detecta_las_columnas_clave(tmp_path: Path):
    """`id.orig_h` y compañía tienen que reconocerse solas."""
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_TSV, encoding="utf-8")
    df = read_zeek(p)

    assert detect_column(df, "src_ip") == "id.orig_h"
    assert detect_column(df, "dst_ip") == "id.resp_h"
    assert detect_column(df, "dst_port") == "id.resp_p"
    assert detect_column(df, "time") == "ts"


# --- Suricata EVE -------------------------------------------------------------


def _eve(tmp_path: Path, eventos: list[dict]) -> Path:
    p = tmp_path / "eve.json"
    p.write_text("\n".join(json.dumps(e) for e in eventos) + "\n", encoding="utf-8")
    return p


EVE_FLOW = {
    "timestamp": "2026-09-19T10:00:00.000000+0000",
    "event_type": "flow",
    "src_ip": "10.0.0.1",
    "src_port": 51234,
    "dest_ip": "93.184.216.34",
    "dest_port": 443,
    "proto": "TCP",
    "flow": {"pkts_toserver": 10, "bytes_toserver": 1420},
}
EVE_ALERT = {
    "timestamp": "2026-09-19T10:00:01.000000+0000",
    "event_type": "alert",
    "src_ip": "10.0.0.2",
    "alert": {"signature": "ET SCAN Nmap", "category": "Attempted Recon"},
}


def test_suricata_filtra_por_event_type(tmp_path: Path):
    """Un EVE mezcla tipos; leerlos juntos da columnas casi vacías."""
    p = _eve(tmp_path, [EVE_FLOW, EVE_ALERT, EVE_FLOW])

    df = read_suricata(p, event_type="flow")

    assert df.height == 2
    assert "alert_signature" not in df.columns


def test_suricata_no_deja_la_columna_event_type_al_filtrar(tmp_path: Path):
    """Constante tras el filtro: no es una característica ni un defecto."""
    p = _eve(tmp_path, [EVE_FLOW, EVE_ALERT, EVE_FLOW])

    assert "event_type" not in read_suricata(p, event_type="flow").columns
    assert "event_type" in read_suricata(p, event_type=None).columns


def test_suricata_aplana_los_structs(tmp_path: Path):
    """`flow.pkts_toserver` tiene que volverse una columna propia.

    Un struct no se puede hashear ni comparar entre splits, que es la mitad de
    lo que hacen los checks.
    """
    p = _eve(tmp_path, [EVE_FLOW])

    df = read_suricata(p, event_type="flow")

    assert "flow_pkts_toserver" in df.columns
    assert df.get_column("flow_pkts_toserver").to_list() == [10]
    assert not any(isinstance(t, pl.Struct) for t in df.schema.values())


def test_suricata_la_firma_sirve_de_etiqueta(tmp_path: Path):
    p = _eve(tmp_path, [EVE_ALERT, EVE_ALERT])

    df = read_suricata(p, event_type="alert")

    assert detect_column(df, "label") == "alert_signature"


def test_suricata_dice_que_tipos_hay(tmp_path: Path):
    """Pedir un tipo que no está tiene que listar los disponibles."""
    p = _eve(tmp_path, [EVE_ALERT])

    with pytest.raises(SuricataFormatError, match="alert"):
        read_suricata(p, event_type="flow")


def test_suricata_rechaza_un_json_cualquiera(tmp_path: Path):
    p = _eve(tmp_path, [{"foo": 1}])

    with pytest.raises(SuricataFormatError, match="event_type"):
        read_suricata(p)


# --- Despacho por extensión ---------------------------------------------------


def test_read_dataset_despacha_zeek(tmp_path: Path):
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_TSV, encoding="utf-8")

    assert read_dataset(p).height == 2


def test_read_dataset_despacha_suricata(tmp_path: Path):
    p = _eve(tmp_path, [EVE_FLOW])

    assert read_dataset(p).height == 1


def test_read_dataset_pasa_el_event_type(tmp_path: Path):
    """Sin esto las alertas son inalcanzables desde `read_dataset`.

    Los flujos son el default razonable, pero las alertas son las que traen
    algo parecido a una etiqueta, asi que hace falta poder pedirlas.
    """
    p = _eve(tmp_path, [EVE_FLOW, EVE_ALERT])

    alertas = read_dataset(p, event_type="alert")

    assert alertas.height == 1
    assert detect_column(alertas, "label") == "alert_signature"


def test_json_lines_que_no_es_eve_se_lee_igual(tmp_path: Path):
    """Un `.json` sin `event_type` no es un EVE, pero sigue siendo legible."""
    p = tmp_path / "datos.json"
    p.write_text('{"a":1,"b":2}\n{"a":3,"b":4}\n', encoding="utf-8")

    df = read_dataset(p)

    assert df.height == 2
    assert df.columns == ["a", "b"]


def test_carpeta_mixta_concatena(tmp_path: Path):
    """Zeek y CSV en la misma carpeta se unen conservando la procedencia."""
    (tmp_path / "conn.log").write_text(ZEEK_TSV, encoding="utf-8")
    (tmp_path / "extra.csv").write_text("ts,uid\n123.0,Cxyz\n", encoding="utf-8")

    df = read_dataset(tmp_path)

    assert df.height == 3
    assert set(df.get_column("__source_file").unique()) == {"conn.log", "extra.csv"}


def test_carpeta_solo_con_pcap_avisa(tmp_path: Path):
    """Extraer flujos tarda minutos: no se hace para una carpeta entera."""
    (tmp_path / "captura.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

    with pytest.raises(FileNotFoundError, match="PCAP"):
        read_dataset(tmp_path)


def test_formato_desconocido_lista_los_validos(tmp_path: Path):
    p = tmp_path / "datos.xlsx"
    p.write_bytes(b"PK\x03\x04")

    with pytest.raises(ValueError, match="no soportado"):
        read_dataset(p)


# --- PCAP ---------------------------------------------------------------------


def test_pcap_sin_nfstream_explica_como_instalarlo(tmp_path: Path):
    """La dependencia es pesada y opcional; el error tiene que decir qué hacer."""
    pytest.importorskip  # noqa: B018
    try:
        import nfstream  # noqa: F401
    except ImportError:
        pass
    else:
        pytest.skip("nfstream está instalado: este test cubre el caso contrario")

    from vigia.io.pcap import PcapReadError, read_pcap

    p = tmp_path / "captura.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1")

    with pytest.raises(PcapReadError, match="nfstream"):
        read_pcap(p)
