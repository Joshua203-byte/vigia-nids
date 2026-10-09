"""Perfiles de datasets conocidos (R17)."""

from __future__ import annotations

import pytest

import vigia
from vigia.profiles import ProfileNotFound, available_profiles, load_profile


def test_cic_ids_2017_esta_disponible():
    assert "cic-ids-2017" in available_profiles()


def test_carga_el_perfil_de_cic_ids_2017():
    perfil = load_profile("cic-ids-2017")

    assert perfil["id"] == "cic-ids-2017"
    assert perfil["column_roles"]["label_col"] == "Label"
    assert perfil["column_roles"]["dst_port_col"] == "Destination Port"
    assert len(perfil["attack_windows"]) > 0
    assert len(perfil["known_attackers"]) > 0
    assert len(perfil["known_issues"]) > 0


def test_perfil_inexistente_lanza_profile_not_found():
    with pytest.raises(ProfileNotFound, match="no existe el perfil 'no-existe'"):
        load_profile("no-existe")


def test_vigia_load_aplica_los_roles_del_perfil(tmp_path):
    path = tmp_path / "cic.csv"
    path.write_text("Destination Port,Label\n80,BENIGN\n443,DoS Hulk\n", encoding="utf-8")

    ctx = vigia.load(path, profile="cic-ids-2017")

    assert ctx.label_col == "Label"
    assert ctx.dst_port_col == "Destination Port"
    assert ctx.config["profile"]["id"] == "cic-ids-2017"


def test_columna_explicita_gana_sobre_el_perfil(tmp_path):
    path = tmp_path / "cic.csv"
    path.write_text(
        "Destination Port,Label,Etiqueta\n80,BENIGN,ok\n443,DoS Hulk,mal\n", encoding="utf-8"
    )

    ctx = vigia.load(path, profile="cic-ids-2017", label_col="Etiqueta")

    assert ctx.label_col == "Etiqueta"


def test_vigia_load_sin_profile_no_agrega_config_de_perfil(tmp_path):
    path = tmp_path / "cic.csv"
    path.write_text("Destination Port,Label\n80,BENIGN\n", encoding="utf-8")

    ctx = vigia.load(path)

    assert "profile" not in ctx.config


def test_perfiles_nuevos_disponibles():
    assert {"cse-cic-ids-2018", "unsw-nb15"} <= set(available_profiles())


def test_cse_cic_ids_2018_ventanas_bien_formadas():
    perfil = load_profile("cse-cic-ids-2018")

    assert len(perfil["attack_windows"]) == 22
    for w in perfil["attack_windows"]:
        assert w["day"].startswith("2018-")
        assert w["start"] < w["end"]  # HH:MM, mismo dia
        assert w["attacker"] and w["victim"]


def test_unsw_nb15_columnas_y_categorias():
    perfil = load_profile("unsw-nb15")

    assert perfil["column_roles"]["label_col"] == "label"
    assert perfil["column_roles"]["category_col"] == "attack_cat"
    assert len(perfil["attack_categories"]) == 9


def test_los_cinco_perfiles_de_r17_estan_disponibles():
    assert {"cic-ids-2017", "cse-cic-ids-2018", "unsw-nb15", "ugr-16", "ctu-13"} <= set(
        available_profiles()
    )


def test_ctu_13_tiene_13_escenarios_consecutivos():
    perfil = load_profile("ctu-13")

    assert [s["scenario"] for s in perfil["scenarios"]] == list(range(1, 14))
    assert perfil["column_roles"]["label_col"] == "Label"
    for s in perfil["scenarios"]:
        assert s["infected_hosts"]
        assert set(s["infected_hosts"]) <= set(perfil["known_attackers"])


def test_ugr_16_ventanas_planificadas_y_aleatorias():
    perfil = load_profile("ugr-16")

    # 12 lotes planificados x 6 ataques; 12 lotes aleatorios de 2 h.
    assert len(perfil["attack_windows"]) == 72
    assert len(perfil["random_batches"]) == 12
    assert {w["label"] for w in perfil["attack_windows"]} == {
        "dos",
        "scan11",
        "scan44",
        "nerisbotnet",
    }
    assert len(perfil["csv_columns"]) == 13
    assert perfil["csv_columns"][-1] == perfil["column_roles"]["label_col"]


def test_ugr_16_se_lee_sin_cabecera_con_los_nombres_del_perfil(tmp_path):
    path = tmp_path / "ugr.csv"
    filas = [
        "2016-07-27 13:43:21,48.380,187.96.221.207,42.219.153.7,53,53,UDP,.A....,0,0,2,209,"
        "background",
        "2016-07-27 13:43:25,50.632,42.219.153.191,62.205.150.146,80,1838,TCP,.AP...,0,0,9,"
        "2082,blacklist",
    ]
    path.write_text("\n".join(filas) + "\n", encoding="utf-8")

    ctx = vigia.load(path, profile="ugr-16")

    assert ctx.df.height == 2  # la primera fila es un dato, no una cabecera
    assert ctx.label_col == "label"
    assert ctx.src_ip_col == "sa"
    assert ctx.dst_port_col == "dp"
    assert ctx.df["label"].to_list() == ["background", "blacklist"]


def test_unsw_nb15_raw_lee_los_crudos_sin_cabecera(tmp_path):
    perfil = load_profile("unsw-nb15-raw")
    assert len(perfil["csv_columns"]) == 49
    assert perfil["csv_columns"][-1] == perfil["column_roles"]["label_col"]

    # Dos filas con el formato de UNSW-NB15_1.csv (49 campos, sin cabecera).
    fila = (
        "59.166.0.0,1390,149.171.126.6,53,udp,CON,0.001055,132,164,31,29,0,0,dns,"
        "500473.9375,621800.9375,2,2,0,0,0,0,66,82,0,0,0,0,1421927414,1421927414,"
        "0.017,0.013,0,0,0,0,0,0,0,0,3,7,1,3,1,1,1,,0"
    )
    path = tmp_path / "UNSW-NB15_1.csv"
    path.write_text(fila + "\n" + fila + "\n", encoding="utf-8")

    ctx = vigia.load(path, profile="unsw-nb15-raw")

    assert ctx.df.height == 2
    assert ctx.df.width == 49
    assert ctx.label_col == "Label"
    assert ctx.src_ip_col == "srcip"
    assert ctx.time_col == "Stime"


def test_unsw_nb15_documenta_la_verdad_de_terreno():
    perfil = load_profile("unsw-nb15")

    assert len(perfil["known_attackers"]) == 4
    assert len(perfil["victim_ips"]) == 10
    assert [d["day"] for d in perfil["capture_days"]] == ["2015-01-22", "2015-02-18"]


def _csv_ctu(tmp_path):
    path = tmp_path / "capture.binetflow"
    path.write_text(
        "SrcAddr,DstAddr,Proto,Sport,Dport,Dur,Label\n"
        "1.1.1.1,2.2.2.2,tcp,1000,80,0.5,flow=Background-TCP-Established\n"
        "1.1.1.1,2.2.2.3,tcp,1001,80,0.6,flow=To-Background-CVUT-DNS-Server\n"
        "147.32.84.165,2.2.2.2,tcp,1002,80,0.7,flow=From-Botnet-V46-TCP-Attempt\n"
        "147.32.84.165,2.2.2.4,tcp,1003,80,0.8,flow=From-Normal-V46-Grill\n"
        "9.9.9.9,147.32.84.165,tcp,1004,80,0.9,flow=To-Botnet-V46-TCP\n"
        "8.8.8.8,2.2.2.2,tcp,1005,80,1.0,algo-no-previsto\n"
        "7.7.7.7,2.2.2.2,tcp,1006,80,1.1,flow=Normal-V46-HTTP-windowsupdate\n",
        encoding="utf-8",
    )
    return path


def test_ctu_13_agrupa_la_etiqueta_por_prefijo(tmp_path):
    ctx = vigia.load(_csv_ctu(tmp_path), profile="ctu-13")

    assert ctx.df["Label"].to_list() == [
        "background",
        "background",
        "botnet",
        "normal",
        "to_botnet",
        "algo-no-previsto",  # lo que no encaja en ningun grupo no se mezcla
        "normal",  # flow=Normal-V46-... (sin From/To) tambien es normal
    ]
    assert ctx.df["__label_original"][2] == "flow=From-Botnet-V46-TCP-Attempt"


def test_la_etiqueta_original_no_cuenta_como_caracteristica(tmp_path):
    ctx = vigia.load(_csv_ctu(tmp_path), profile="ctu-13")

    assert "__label_original" not in ctx.feature_cols
    assert "Label" not in ctx.feature_cols


def test_un_perfil_sin_label_groups_deja_la_etiqueta_como_esta(tmp_path):
    path = tmp_path / "cic.csv"
    path.write_text("Destination Port,Label\n80,BENIGN\n", encoding="utf-8")

    ctx = vigia.load(path, profile="cic-ids-2017")

    assert ctx.df["Label"].to_list() == ["BENIGN"]
    assert "__label_original" not in ctx.df.columns
