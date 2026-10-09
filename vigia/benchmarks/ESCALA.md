# Benchmark de escala

Generado por `benchmarks/escala.py`. Auditoría completa (todos los
checks del módulo 1) sobre datasets sintéticos, un proceso aparte por
tamaño para que el pico de memoria no se contamine entre corridas.

| Filas | Tiempo | Pico RSS | Check más caro |
|---|---|---|---|
| 1,000,000 | 23.54 s | 821 MB | labels.noise |
| 5,000,000 | 18.92 s | 1665 MB | labels.noise |
| 10,000,000 | 17.60 s | 1919 MB | shortcut.single_feature |
| 25,000,000 | 40.69 s | 3554 MB | shortcut.single_feature |

## Los tres checks más caros, por tamaño

**1,000,000 filas:**
- `labels.noise`: 21.951 s
- `shortcut.single_feature`: 1.111 s
- `labels.conflict`: 0.253 s

**5,000,000 filas:**
- `labels.noise`: 11.853 s
- `shortcut.single_feature`: 4.953 s
- `labels.conflict`: 1.142 s

**10,000,000 filas:**
- `shortcut.single_feature`: 9.767 s
- `labels.noise`: 3.520 s
- `labels.conflict`: 2.286 s

**25,000,000 filas:**
- `shortcut.single_feature`: 26.333 s
- `labels.conflict`: 5.611 s
- `labels.noise`: 3.606 s

