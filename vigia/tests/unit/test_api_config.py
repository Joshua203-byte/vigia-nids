"""Configuracion de la API: un solo lugar, validada al arrancar (AUDITORIA-1.0.md, SEC-05)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from vigia.api.app import app
from vigia.api.config import ConfigError, load_settings


def test_los_valores_por_defecto_son_seguros(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("VIGIA_MAX_UPLOAD_MB", "VIGIA_RATE_LIMIT_PER_MINUTE"):
        monkeypatch.delenv(var, raising=False)
    s = load_settings()
    assert s.max_upload_bytes == 200 * 1024 * 1024
    assert s.rate_limit_per_minute == 30


@pytest.mark.parametrize("valor", ["abc", "-1", "1.5", ""])
def test_un_limite_de_subida_invalido_se_rechaza_con_el_nombre_de_la_variable(
    monkeypatch: pytest.MonkeyPatch, valor: str
) -> None:
    monkeypatch.setenv("VIGIA_MAX_UPLOAD_MB", valor)
    with pytest.raises(ConfigError, match="VIGIA_MAX_UPLOAD_MB"):
        load_settings()


@pytest.mark.parametrize("valor", ["abc", "-3", "0"])
def test_un_limite_de_peticiones_invalido_se_rechaza(
    monkeypatch: pytest.MonkeyPatch, valor: str
) -> None:
    monkeypatch.setenv("VIGIA_RATE_LIMIT_PER_MINUTE", valor)
    with pytest.raises(ConfigError, match="VIGIA_RATE_LIMIT_PER_MINUTE"):
        load_settings()


def test_el_arranque_falla_con_configuracion_invalida(monkeypatch: pytest.MonkeyPatch) -> None:
    """El error aparece al levantar el servidor, no en la primera peticion."""
    monkeypatch.setenv("VIGIA_MAX_UPLOAD_MB", "mucho")
    with pytest.raises(ConfigError), TestClient(app):
        pass


@pytest.mark.parametrize(
    "variable",
    [
        "VIGIA_UPLOAD_TTL_MINUTES",
        "VIGIA_STORAGE_QUOTA_MB",
        "VIGIA_MAX_CONCURRENT_JOBS",
        "VIGIA_MAX_QUEUED_JOBS",
        "VIGIA_REPORT_TTL_MINUTES",
        "VIGIA_MAX_STORED_JOBS",
        "VIGIA_MAX_ROWS",
        "VIGIA_MAX_EXPANDED_MB",
    ],
)
def test_las_variables_de_disco_y_trabajos_tambien_se_validan(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    monkeypatch.setenv(variable, "-1")
    with pytest.raises(ConfigError, match=variable):
        load_settings()
    monkeypatch.setenv(variable, "x")
    with pytest.raises(ConfigError, match=variable):
        load_settings()


def test_en_produccion_el_arranque_falla_sin_clave_de_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """La imagen de produccion no puede arrancar abierta en silencio (SEC-09)."""
    monkeypatch.setenv("VIGIA_ENV", "production")
    monkeypatch.delenv("VIGIA_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="VIGIA_API_KEY"):
        load_settings()
    with pytest.raises(ConfigError), TestClient(app):
        pass
    monkeypatch.setenv("VIGIA_API_KEY", "")
    with pytest.raises(ConfigError, match="VIGIA_API_KEY"):
        load_settings()
    monkeypatch.setenv("VIGIA_API_KEY", "una-clave")
    assert load_settings().env == "production"


def test_en_desarrollo_sin_clave_sigue_arrancando(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VIGIA_ENV", raising=False)
    monkeypatch.delenv("VIGIA_API_KEY", raising=False)
    assert load_settings().env == "development"


def test_un_entorno_desconocido_se_rechaza(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIGIA_ENV", "prod")  # un typo no puede saltarse el control
    with pytest.raises(ConfigError, match="VIGIA_ENV"):
        load_settings()


@pytest.mark.parametrize("valor", ["*", "http://a.example, *", " * "])
def test_cors_con_comodin_hace_fallar_el_arranque(
    monkeypatch: pytest.MonkeyPatch, valor: str
) -> None:
    monkeypatch.setenv("VIGIA_CORS_ORIGINS", valor)
    with pytest.raises(ConfigError, match="VIGIA_CORS_ORIGINS"):
        load_settings()


def test_cors_no_permite_credenciales() -> None:
    """La clave viaja en una cabecera propia, no en cookies: permitir
    credenciales solo agrandaba lo que un origen ajeno puede pedir (SEC-12)."""
    with TestClient(app) as c:
        r = c.options(
            "/api/v1/checks",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in r.headers


def test_el_tope_de_memoria_estimada_sigue_al_pico_medido(monkeypatch: pytest.MonkeyPatch) -> None:
    """El pico medido de una auditoria es ~8,4 veces la memoria cruda (5,4 GiB para
    1 M x 80 = 640 MB). Un tope de 4 GiB estimados dejaba pasar datasets que
    necesitan ~34 GiB; el defecto queda en 700 MB, que admite 1 M x 80
    (VERIFICACION-1.0.md, VER-09)."""
    monkeypatch.delenv("VIGIA_MAX_EXPANDED_MB", raising=False)
    assert load_settings().max_expanded_mb == 700


def test_avisa_si_el_tope_por_el_factor_supera_la_memoria(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigia.api import config

    monkeypatch.delenv("VIGIA_MAX_EXPANDED_MB", raising=False)
    monkeypatch.setattr(config, "container_memory_bytes", lambda: 2 * 1024**3)
    aviso = config.memory_warning(load_settings())
    assert aviso and "VIGIA_MAX_EXPANDED_MB" in aviso and "700" in aviso

    monkeypatch.setattr(config, "container_memory_bytes", lambda: 6 * 1024**3)
    assert config.memory_warning(load_settings()) is None  # el compose de produccion

    monkeypatch.setattr(config, "container_memory_bytes", lambda: None)
    assert config.memory_warning(load_settings()) is None  # sin dato, no se inventa


def test_el_arranque_loguea_el_aviso_de_memoria(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from vigia.api import config

    monkeypatch.setattr(config, "container_memory_bytes", lambda: 1024**3)
    with caplog.at_level(logging.WARNING, logger="vigia.api"), TestClient(app):
        pass
    assert any("VIGIA_MAX_EXPANDED_MB" in r.getMessage() for r in caplog.records)
