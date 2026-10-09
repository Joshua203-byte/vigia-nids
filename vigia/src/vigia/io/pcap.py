"""Extraccion de flujos desde PCAP (R14).

Un PCAP son paquetes sueltos; los checks de Vigia trabajan sobre flujos. La
conversion la hace NFStream, que es una dependencia opcional pesada (arrastra
libpcap) y por eso no entra en la instalacion base.

**Por que NFStream y no CICFlowMeter.** Los datasets CIC se generaron con
CICFlowMeter, y sus defectos documentados --duraciones negativas, division por
cero en las tasas, el centinela -1 en las ventanas TCP-- vienen de ahi. Usar la
misma herramienta para extraer flujos reproduciria esos mismos artefactos, y
Vigia existe justamente para detectarlos.

**Esto no reproduce las 78 columnas de CIC-IDS2017.** NFStream calcula su
propio conjunto de metricas. Un modelo entrenado con features de CICFlowMeter
no se puede evaluar directamente sobre flujos de NFStream, y al reves tampoco.
Lo que si permite es auditar la calidad de una captura propia.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

#: Extensiones que trae una captura. `.pcapng` es el formato actual; `.cap` lo
#: escriben algunas herramientas viejas.
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}

#: Segundos de inactividad tras los cuales un flujo se da por terminado. 120 es
#: el valor por defecto de NFStream y coincide con el de CICFlowMeter, asi que
#: los flujos son comparables en duracion aunque no en columnas.
IDLE_TIMEOUT = 120
#: Duracion maxima de un flujo, para que una conexion larga no quede abierta
#: hasta el final de la captura.
ACTIVE_TIMEOUT = 1800


class PcapReadError(RuntimeError):
    """No se pudo extraer flujos del PCAP."""


def read_pcap(
    path: str | Path,
    *,
    idle_timeout: int = IDLE_TIMEOUT,
    active_timeout: int = ACTIVE_TIMEOUT,
    statistical: bool = True,
) -> pl.DataFrame:
    """Extrae flujos de una captura y los devuelve como DataFrame.

    ``statistical=True`` agrega las metricas por flujo (bytes, paquetes,
    tiempos entre llegadas), que es lo que hace util al resultado para
    auditarlo. Con ``False`` solo salen las cinco tuplas, que es mas rapido
    pero no da nada que medir.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"no existe: {p}")

    try:
        from nfstream import NFStreamer
    except ImportError as exc:
        raise PcapReadError(
            "leer PCAP requiere nfstream: pip install 'vigia-nids[pcap]'. "
            "En Linux hace falta ademas libpcap-dev."
        ) from exc

    try:
        streamer = NFStreamer(
            source=str(p),
            statistical_analysis=statistical,
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
        )
        df = pl.from_pandas(streamer.to_pandas())
    except Exception as exc:  # pragma: no cover - depende de libpcap
        raise PcapReadError(f"{p.name}: no se pudo extraer flujos ({exc})") from exc

    if df.is_empty():
        raise PcapReadError(
            f"{p.name}: no se extrajo ningun flujo. "
            "La captura puede estar vacia, truncada o cifrada a nivel de enlace."
        )
    return df
