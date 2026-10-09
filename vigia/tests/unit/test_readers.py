"""Lectura de datasets y detección automática de columnas."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.io.readers import detect_column, read_dataset, strip_column_names


def test_lee_csv_que_no_es_utf8(tmp_path):
    """CIC-IDS2017 etiqueta los ataques web con un guion en Windows-1252.

    Polars rechaza el archivo entero por ese byte, así que sin el respaldo
    de codificación uno de los ocho días del dataset es imposible de leer.
    """
    path = tmp_path / "webattacks.csv"
    path.write_bytes(
        b"Destination Port,Label\r\n"
        b"80,BENIGN\r\n"
        b"443,Web Attack \x96 Brute Force\r\n"  # 0x96 = guion largo en cp1252
        b"8080,Web Attack \x96 XSS\r\n"
    )
    df = read_dataset(path)
    assert df.height == 3
    etiquetas = df.get_column("Label").to_list()
    assert "Web Attack – Brute Force" in etiquetas
    assert "BENIGN" in etiquetas


def test_csv_utf8_no_pasa_por_el_respaldo(tmp_path):
    """El camino normal sigue siendo el de UTF-8, con acentos incluidos."""
    path = tmp_path / "normal.csv"
    path.write_text("puerto,Label\n80,BENIGN\n443,Intrusión\n", encoding="utf-8")
    df = read_dataset(path)
    assert df.get_column("Label").to_list() == ["BENIGN", "Intrusión"]


def test_detecta_columnas_de_cicflowmeter():
    df = pl.DataFrame(
        {
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["10.0.0.2"],
            "Timestamp": ["2026-01-01 00:00:00"],
            "Label": ["BENIGN"],
            "split": ["train"],
        }
    )
    assert detect_column(df, "label") == "Label"
    assert detect_column(df, "time") == "Timestamp"
    assert detect_column(df, "src_ip") == "Source IP"
    assert detect_column(df, "dst_ip") == "Destination IP"
    assert detect_column(df, "split") == "split"


def test_ts_no_coincide_dentro_de_pkts_fwd():
    """Regresión: 'ts' como subcadena hacía que 'pkts_fwd' pasara por columna
    de tiempo, y el check temporal corría sobre un conteo de paquetes."""
    df = pl.DataFrame({"pkts_fwd": [1, 2], "bytes_fwd": [10, 20]})
    assert detect_column(df, "time") is None


def test_sin_coincidencia_devuelve_none():
    df = pl.DataFrame({"a": [1], "b": [2]})
    assert detect_column(df, "label") is None
    assert detect_column(df, "src_ip") is None


def test_strip_column_names():
    df = pl.DataFrame({" Destination Port ": [80]})
    assert strip_column_names(df).columns == ["Destination Port"]


def test_lee_csv_y_parquet(tmp_path):
    df = pl.DataFrame({"a": [1, 2], "label": ["x", "y"]})
    csv, pq = tmp_path / "d.csv", tmp_path / "d.parquet"
    df.write_csv(csv)
    df.write_parquet(pq)
    assert read_dataset(csv).height == 2
    assert read_dataset(pq).height == 2


def test_lee_carpeta_y_conserva_procedencia(tmp_path):
    """Los datasets CIC vienen partidos en un archivo por día."""
    for day in ("lunes", "martes"):
        pl.DataFrame({"a": [1], "label": ["x"]}).write_csv(tmp_path / f"{day}.csv")

    df = read_dataset(tmp_path)
    assert df.height == 2
    assert set(df.get_column("__source_file").to_list()) == {"lunes.csv", "martes.csv"}


def test_formato_no_soportado(tmp_path):
    # `.pcap` dejo de servir de ejemplo al agregarse el lector de capturas
    # (R14). Un `.xlsx` sigue sin soportarse y el error tiene que listar lo
    # que si se acepta, para que no haya que adivinarlo.
    path = tmp_path / "datos.xlsx"
    path.write_bytes(b"PK\x03\x04")
    with pytest.raises(ValueError, match="no soportado"):
        read_dataset(path)


def test_archivo_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_dataset(tmp_path / "no_existe.csv")


def test_carpeta_sin_datasets(tmp_path):
    (tmp_path / "vacia").mkdir()
    with pytest.raises(FileNotFoundError):
        read_dataset(tmp_path / "vacia")


def test_lee_binetflow_como_csv(tmp_path):
    from vigia.io.readers import read_dataset

    path = tmp_path / "capture20110815-2.binetflow.2format"
    path.write_text("SrcAddr,Label\n1.1.1.1,flow=Background\n", encoding="utf-8")

    df = read_dataset(path)

    assert df.columns == ["SrcAddr", "Label"]


def test_csv_no_convierte_decimales_tardios_en_nulos(tmp_path):
    """Si las primeras filas de una columna son enteras y mas adelante hay
    decimales, polars (ignore_errors) los volvia nulos sin avisar."""
    from vigia.io.readers import read_dataset

    filas = ["a,b,c"] + [f"{i},{i},x" for i in range(12_000)]
    filas += ["150.5,2.25,x", "7,8,x"]
    path = tmp_path / "datos.csv"
    path.write_text("\n".join(filas) + "\n", encoding="utf-8")

    df = read_dataset(path)

    assert df["a"].null_count() == 0
    assert df["b"].null_count() == 0
    assert 150.5 in df["a"].to_list()


def _csv_con_infinitos(tmp_path, *, al_principio: bool, encoding: str = "utf-8"):
    """Tasas con `Infinity` (como escribe Java/CICFlowMeter) al principio, dentro
    de la ventana de inferencia, o despues de ella."""
    filas = ["Flow Bytes/s,Label"] + [f"{i * 1.5},BENIGN" for i in range(12_000)]
    pos = 5 if al_principio else 11_000
    filas[pos] = "Infinity,DoS"
    filas[pos + 1] = "-Infinity,DoS"
    filas[pos + 2] = "NaN,DoS"
    path = tmp_path / "cic.csv"
    path.write_bytes(("\n".join(filas) + "\n").encode(encoding))
    return path


@pytest.mark.parametrize("al_principio", [True, False])
def test_csv_conserva_infinity_y_nan_como_valores_reales(tmp_path, al_principio):
    """`Infinity`, `-Infinity` y `NaN` estaban en `null_values`: los infinitos de
    CICFlowMeter se leian como nulos y `validity.nan_inf` los reportaba como
    "low, 0 infinitos" (AUDITORIA-1.0.md, SCI-07)."""
    df = read_dataset(_csv_con_infinitos(tmp_path, al_principio=al_principio))

    col = df["Flow Bytes/s"]
    assert col.dtype == pl.Float64
    assert int(col.is_infinite().sum()) == 2
    assert int(col.is_nan().sum()) == 1
    assert col.null_count() == 0


def test_validity_nan_inf_ve_los_infinitos_del_csv(tmp_path):
    import vigia

    ctx = vigia.load(_csv_con_infinitos(tmp_path, al_principio=True))
    rep = vigia.audit(ctx, checks="validity.nan_inf")
    (f,) = rep.findings
    assert f.metric["inf"] == 2.0
    assert f.severity == "high"


def test_streaming_ve_los_mismos_infinitos(tmp_path):
    from vigia.core.streaming import run_streaming_audit

    rep = run_streaming_audit(_csv_con_infinitos(tmp_path, al_principio=True), label_col="Label")
    (f,) = [x for x in rep.findings if x.check_id == "validity.nan_inf"]
    assert f.metric["inf"] == 2.0
    assert f.severity == "high"


def test_infinitos_tambien_con_el_respaldo_cp1252(tmp_path):
    """El reintento en cp1252 relee el archivo por otro camino: tiene que
    conservar los infinitos igual."""
    path = tmp_path / "web.csv"
    filas = ["rate,Label"] + [f"{i * 1.5},BENIGN" for i in range(50)]
    filas += ["Infinity,Web Attack \x96 Brute Force"]
    path.write_bytes(("\n".join(filas) + "\n").encode("latin-1"))

    df = read_dataset(path)
    assert int(df["rate"].is_infinite().sum()) == 1


def test_una_columna_de_texto_no_se_convierte_a_numero(tmp_path):
    path = tmp_path / "texto.csv"
    path.write_text("nombre,rate\nNaN,1.5\nana,2.5\n", encoding="utf-8")

    df = read_dataset(path)
    assert df["nombre"].dtype == pl.String
    assert df["nombre"].to_list() == ["NaN", "ana"]


def test_csv_con_columna_entera_sigue_siendo_entera(tmp_path):
    from vigia.io.readers import read_dataset

    path = tmp_path / "datos.csv"
    path.write_text("puerto,etiqueta\n80,0\n443,1\n,0\n", encoding="utf-8")

    df = read_dataset(path)

    assert df["puerto"].dtype == pl.Int64
    assert df["etiqueta"].dtype == pl.Int64
    assert df["puerto"].null_count() == 1
