"""Genera un dataset sintético con los errores típicos de CIC-IDS2017.

Sirve para probar Vigía sin descargar decenas de gigas, y como control de que
los checks encuentran lo que deben. Los errores sembrados son:

  * duplicados exactos, algunos cruzando entre entrenamiento y prueba;
  * la IP del atacante presente como característica (atajo);
  * un puerto imposible (> 65535);
  * infinitos en una columna de tasa (división entre duración cero);
  * una columna constante;
  * el mismo host atacante en ambos splits.

Uso:
    python benchmarks/make_demo_dataset.py data/demo_flows.csv
    vigia audit data/demo_flows.csv --report out/
"""

from __future__ import annotations

import math
import random
import sys
from pathlib import Path

import polars as pl

SEED = 42
N_BENIGN = 400
N_ATTACK = 120

ATTACKER_IPS = ["205.174.165.73", "205.174.165.80"]
VICTIM_IPS = [f"192.168.10.{i}" for i in range(5, 25)]


def build() -> pl.DataFrame:
    rng = random.Random(SEED)
    rows: list[dict[str, object]] = []

    for _ in range(N_BENIGN):
        duration = round(rng.uniform(0.05, 12.0), 4)
        n_bytes = rng.randint(120, 8000)
        rows.append(
            {
                "Source IP": rng.choice(VICTIM_IPS),
                "Destination IP": rng.choice(VICTIM_IPS),
                "Destination Port": rng.choice([80, 443, 53, 22, 8080]),
                "Flow Duration": duration,
                "Total Fwd Packets": rng.randint(1, 40),
                "Total Length of Fwd Packets": n_bytes,
                "Flow Bytes/s": round(n_bytes / duration, 2),
                "Protocolo": 6,  # constante: sembrado a propósito
                "Timestamp": f"2017-07-0{rng.randint(3, 5)} {rng.randint(9, 17):02d}:{rng.randint(0, 59):02d}:00",
                "Label": "BENIGN",
            }
        )

    for i in range(N_ATTACK):
        # Los flujos de DoS son muy repetitivos: duración casi cero y tamaños
        # idénticos. Aquí eso produce duplicados naturales, como en el original.
        duration = 0.0 if i % 5 == 0 else round(rng.uniform(0.001, 0.05), 4)
        n_bytes = rng.choice([0, 6, 6, 6, 12])
        rows.append(
            {
                "Source IP": rng.choice(ATTACKER_IPS),  # atajo: solo el atacante
                "Destination IP": rng.choice(VICTIM_IPS[:3]),
                "Destination Port": 80,
                "Flow Duration": duration,
                "Total Fwd Packets": rng.choice([1, 2]),
                "Total Length of Fwd Packets": n_bytes,
                # División entre cero → infinito, igual que CICFlowMeter.
                "Flow Bytes/s": math.inf if duration == 0 else round(n_bytes / duration, 2),
                "Protocolo": 6,
                "Timestamp": f"2017-07-0{rng.randint(3, 5)} {rng.randint(9, 17):02d}:{rng.randint(0, 59):02d}:00",
                "Label": "DoS Hulk",
            }
        )

    rng.shuffle(rows)

    # Split aleatorio: el error metodológico que queremos que Vigía detecte.
    for i, row in enumerate(rows):
        row["split"] = "train" if i < len(rows) * 0.7 else "test"

    # Un puerto imposible, por un desalineamiento de columnas.
    rows[0]["Destination Port"] = 70001

    df = pl.DataFrame(rows)

    # Duplicados que cruzan entre splits: copiamos filas de train hacia test.
    train_rows = df.filter(pl.col("split") == "train").head(25)
    crossing = train_rows.with_columns(pl.lit("test").alias("split"))
    return pl.concat([df, crossing], how="vertical")


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "data/demo_flows.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    df = build()
    df.write_csv(out)
    print(f"{df.height:,} filas × {df.width} columnas escritas en {out}")


if __name__ == "__main__":
    main()
