"""Fixtures: datasets diminutos con errores sembrados a propósito."""

from __future__ import annotations

import polars as pl
import pytest

from vigia.core.context import AuditContext


@pytest.fixture(autouse=True)
def _sin_subidas_heredadas(request: pytest.FixtureRequest):
    """En los tests de la API, cada test arranca sin subidas de los anteriores.

    El registro de subidas es global al proceso. Sin esto, una subida sin trabajo
    que dejo otro test aparecia en lo que purgaba el siguiente: con el reloj falso
    en 1000 y `time.monotonic()` real (el tiempo desde que arranco la maquina) el
    resultado dependia del sistema, y en el CI de Linux fallaba (VERIFICACION-1.0.md,
    VER-02).
    """
    if not request.module.__name__.split(".")[-1].startswith("test_api"):
        yield
        return
    from vigia.api.storage import reset_uploads

    reset_uploads()
    yield
    reset_uploads()


def _ctx(df: pl.DataFrame, **kwargs) -> AuditContext:
    defaults = dict(path="memoria", sha256="0" * 64, label_col="label")
    defaults.update(kwargs)
    return AuditContext(df=df, **defaults)


@pytest.fixture
def clean_flows() -> pl.DataFrame:
    """Dataset limpio, usado como control de falsos positivos.

    Deliberadamente no tiene: filas repetidas, columnas que predigan la
    etiqueta por sí solas, hosts compartidos entre splits ni solapamiento
    temporal. Vigía no debería reportar nada grave sobre él.
    """
    n = 120
    labels = ["attack" if (i * 13) % 7 < 3 else "benign" for i in range(n)]
    return pl.DataFrame(
        {
            # Valores distintos por fila (sin duplicados) pero sin relación con
            # la etiqueta: ninguna columna sola la predice.
            "duration": [round(0.5 + i * 0.37, 2) for i in range(n)],
            "bytes_fwd": [100 + i * 7 for i in range(n)],
            "pkts_fwd": [1 + (i * 3) % 40 for i in range(n)],
            # Pocos hosts, y los de prueba son disjuntos de los de entrenamiento.
            "host": [f"10.0.0.{i % 6}" if i < 90 else f"10.9.9.{i % 4}" for i in range(n)],
            # La otra punta de la conexión y los puertos: completan la 5-tupla
            # para que `leak.session` pueda correr. Cada fila es una conexión
            # distinta, así que tampoco hay fuga por sesión.
            "peer": [f"8.8.8.{i % 3}" if i < 90 else f"1.1.1.{i % 3}" for i in range(n)],
            "sport": [1024 + i for i in range(n)],
            "dport": [443 if i % 2 else 80 for i in range(n)],
            "proto": [6 if i % 3 else 17 for i in range(n)],
            # Entrenamiento en enero, prueba en marzo: corte temporal estricto.
            "moment": [
                f"2026-01-{(i // 6) + 1:02d} 08:{i % 60:02d}:00"
                if i < 90
                else f"2026-03-{((i - 90) // 6) + 1:02d} 08:{i % 60:02d}:00"
                for i in range(n)
            ],
            "label": labels,
            "split": ["train" if i < 90 else "test" for i in range(n)],
        }
    )


@pytest.fixture
def clean_ctx(clean_flows: pl.DataFrame) -> AuditContext:
    return _ctx(
        clean_flows,
        split_col="split",
        time_col="moment",
        src_ip_col="host",
        dst_ip_col="peer",
        src_port_col="sport",
        dst_port_col="dport",
        protocol_col="proto",
    )


@pytest.fixture
def make_ctx():
    """Fábrica de contextos para tests que arman su propio DataFrame."""
    return _ctx
