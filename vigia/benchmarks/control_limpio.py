"""Genera un dataset sintético SIN defectos, como control de falsos positivos.

`make_demo_dataset.py` siembra errores para comprobar que Vigía los encuentra.
Este hace lo contrario: un dataset de flujos bien armado, para comprobar que
Vigía **no** inventa problemas. Si una auditoría de este archivo da rojo, hay un
falso positivo.

Qué cuida:

  * ningún duplicado, exacto ni casi: cada valor continuo es un número al azar;
  * ninguna columna constante, nula, infinita o fuera de rango;
  * ninguna característica que por sí sola delate la etiqueta: cada una aporta
    una señal débil y solo la combinación de varias clasifica bien;
  * un split limpio: el entrenamiento es anterior a la prueba, y los hosts de
    origen y de destino son distintos en cada lado;
  * ninguna conexión repartida entre splits;
  * clases con ejemplos de sobra.

Uso:
    python benchmarks/control_limpio.py out/control_limpio.parquet
    vigia audit out/control_limpio.parquet --split-col split
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import polars as pl

SEED = 7

#: Proporción de cada clase.
CLASSES = {"benign": 0.70, "dos": 0.12, "scan": 0.10, "bruteforce": 0.08}

#: Cuánto se separa la media de cada clase en cada característica, en
#: desviaciones estándar. Con 14 características a 2,5 cada una sola clasifica
#: apenas por encima del azar y juntas llegan a una exactitud alta.
SHIFT = 2.5
N_FEATURES = 14

PROTOCOLS = ["tcp", "udp", "icmp"]
#: Puertos destino por clase: se solapan, ninguno determina la clase.
PORTS = {
    "benign": ([80, 443, 53, 22, 8080, 25], [0.30, 0.30, 0.20, 0.08, 0.07, 0.05]),
    "dos": ([80, 443, 53, 22, 8080, 25], [0.35, 0.25, 0.10, 0.08, 0.15, 0.07]),
    "scan": ([80, 443, 53, 22, 8080, 25], [0.15, 0.15, 0.10, 0.30, 0.15, 0.15]),
    "bruteforce": ([80, 443, 53, 22, 8080, 25], [0.10, 0.10, 0.05, 0.50, 0.10, 0.15]),
}


def build(
    n: int = 100_000,
    seed: int = SEED,
    shift: float = SHIFT,
    heavy_tail: bool = True,
    label_noise: float = 0.0,
) -> pl.DataFrame:
    """``heavy_tail`` pasa las características por una exponencial (positivas y
    asimétricas, como las magnitudes de red). ``label_noise`` cambia al azar esa
    fracción de etiquetas, para medir cuánto del ruido real detecta Vigía."""
    rng = np.random.default_rng(seed)
    names = list(CLASSES)
    labels = rng.choice(names, size=n, p=list(CLASSES.values()))

    # Una dirección de cambio distinta por clase y por característica.
    centers = {c: rng.choice([-1.0, 0.0, 1.0], size=N_FEATURES) * shift for c in names}
    centers["benign"] = np.zeros(N_FEATURES)
    x = np.empty((n, N_FEATURES))
    for c in names:
        idx = labels == c
        x[idx] = rng.normal(centers[c], 1.0, size=(idx.sum(), N_FEATURES))
    if heavy_tail:
        x = np.exp(x * 0.8 + 2.0)

    # El entrenamiento va primero en el tiempo (70 %) y la prueba después.
    is_train = np.arange(n) < int(n * 0.7)
    split = np.where(is_train, "train", "test")
    start = np.datetime64("2024-03-01T00:00:00")
    seconds = np.sort(rng.integers(0, 14 * 86_400, size=n))
    timestamp = start + seconds.astype("timedelta64[s]")

    # Hosts distintos en cada split, de origen y de destino.
    def ips(prefix: str, pool: int, size: int) -> np.ndarray:
        host = rng.integers(1, pool + 1, size=size)
        return np.array([f"{prefix}.{h // 250}.{h % 250 + 1}" for h in host])

    src = np.where(is_train, ips("10.1", 4000, n), ips("10.3", 4000, n))
    dst = np.where(is_train, ips("10.2", 800, n), ips("10.4", 800, n))

    dst_port = np.empty(n, dtype=np.int64)
    for c in names:
        idx = labels == c
        ports, probs = PORTS[c]
        dst_port[idx] = rng.choice(ports, size=idx.sum(), p=probs)

    data: dict[str, object] = {
        "timestamp": timestamp.astype("datetime64[us]"),
        "src_ip": src,
        "dst_ip": dst,
        # Puerto de origen efimero y al azar: junto con el resto no repite 5-tupla.
        "src_port": rng.integers(1024, 65536, size=n),
        "dst_port": dst_port,
        "protocol": rng.choice(PROTOCOLS, size=n, p=[0.75, 0.20, 0.05]),
    }
    for i in range(N_FEATURES):
        data[f"feature_{i:02d}"] = np.round(x[:, i], 6)
    observed = labels.copy()
    if label_noise > 0:
        flip = rng.random(n) < label_noise
        observed[flip] = rng.choice(names, size=int(flip.sum()))
    data["label"] = observed
    data["split"] = split
    return pl.DataFrame(data)


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "out/control_limpio.parquet")
    out.parent.mkdir(parents=True, exist_ok=True)
    df = build()
    df.write_parquet(out)
    print(f"{out}: {df.height:,} filas x {df.width} columnas")
    print(df.group_by("label").len().sort("len", descending=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
