"""Módulo 3 — monitor de deriva (sección 10 del documento maestro).

Avisa cuando el modelo deja de estar al día: el tráfico de hoy ya no se parece
al que se usó para entrenarlo, así que sus métricas de laboratorio dejaron de
describir lo que hace en producción.

Se compara un lote nuevo contra una referencia. Cuatro cosas pueden cambiar
(sección 10.1):

| Tipo | Qué cambia | Check |
|---|---|---|
| Datos (covariate shift) | La distribución de cada característica | `drift.feature` |
| Datos (covariate shift) | La distribución conjunta | `drift.covariate` |
| Etiquetas (prior shift) | La proporción de cada clase | `drift.prior` |
| Concepto | La relación entre características y etiqueta | `drift.concept` |
| Esquema | Columnas nuevas, faltantes o con otro tipo | `drift.schema` |

Los cinco necesitan `ctx.reference`, así que no corren en una auditoría
normal. `vigia drift actual.parquet --reference referencia.parquet`.

**La deriva no es un defecto del dataset.** Un dataset puede estar perfecto y
aun así haber derivado: la red cambió, apareció una aplicación nueva, el
atacante cambió de técnica. Por eso es un módulo aparte y no un check más del
auditor: lo que hay que hacer al respecto —reentrenar— es distinto.
"""

from __future__ import annotations

from vigia.drift import checks  # noqa: F401  (el import dispara el registro)
from vigia.drift.metrics import js_divergence, ks_statistic, psi

__all__ = ["checks", "js_divergence", "ks_statistic", "psi"]
