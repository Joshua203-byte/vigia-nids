"""AuditContext: todo lo que un check necesita saber del dataset."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import cached_property
from typing import Any

import polars as pl

from vigia.core.hashing import row_hashes


class CheckSkipped(Exception):
    """Un check no puede correr sobre este dataset (falta una columna, por ejemplo).

    No es un error: el motor lo registra en ``Report.skipped`` y sigue.
    """


@dataclass
class AuditContext:
    """Contexto compartido por todos los checks de una ejecución.

    Los cálculos caros (hashes de fila, columnas numéricas) se hacen una sola
    vez y se comparten, tal como describe la sección 7.1: núcleo común.
    """

    df: pl.DataFrame
    path: str = ""
    sha256: str = ""
    label_col: str | None = None
    split_col: str | None = None
    time_col: str | None = None
    src_ip_col: str | None = None
    dst_ip_col: str | None = None
    src_port_col: str | None = None
    dst_port_col: str | None = None
    protocol_col: str | None = None
    seed: int = 42
    #: Columnas de rol (tiempo, IPs) que el usuario declaró con una opción o con
    #: un perfil. Las que solo se detectaron por nombre no entran: si nadie
    #: dijo que son metadatos, se siguen tratando como posibles identificadores.
    declared_roles: frozenset[str] = frozenset()
    config: dict[str, Any] = field(default_factory=dict)
    #: Dataset de referencia contra el cual comparar (módulo 3, deriva). Los
    #: checks del auditor lo ignoran: un dataset se audita contra sí mismo.
    #: Los de deriva lo exigen con `require("reference")`.
    reference: pl.DataFrame | None = field(default=None, repr=False)

    # ---- atajos de acceso -------------------------------------------------

    @property
    def n_rows(self) -> int:
        return self.df.height

    @property
    def n_cols(self) -> int:
        return self.df.width

    def require(self, *attrs: str) -> None:
        """Marca el check como saltado si falta alguno de estos atributos."""
        for attr in attrs:
            if getattr(self, attr, None) is None:
                raise CheckSkipped(f"requiere '{attr}' (no fue especificado ni detectado)")

    def option(self, key: str, default: Any) -> Any:
        return self.config.get(key, default)

    def with_df(self, df: pl.DataFrame) -> AuditContext:
        """El mismo contexto (columnas, roles, semilla, configuracion) sobre otro DataFrame.

        Es lo que hacen las correcciones encadenadas y la comparacion
        antes/despues. Antes se reconstruia el contexto a mano en tres lugares
        y los tres olvidaban `declared_roles`: `drop_duplicates` volvia a meter
        la hora y las IPs declaradas en la clave y no quitaba los duplicados
        que `dup.exact` reportaba (AUDITORIA-1.0.md, COR-01).

        `replace` pasa por `__init__` con los campos declarados, asi que las
        caches de `cached_property` (que viven en `__dict__`) no se copian:
        los hashes y `shared` se recalculan sobre el DataFrame nuevo.
        """
        return replace(self, df=df)

    # ---- derivados cacheados ---------------------------------------------

    @cached_property
    def feature_cols(self) -> list[str]:
        """Columnas que no son etiqueta, split ni metadatos de la ejecución.

        Las que empiezan con ``__`` las agrega Vigía al leer (``__source_file``),
        no vienen del dataset. Si se colaran aquí, el hash de fila incluiría el
        nombre del archivo y dos flujos idénticos capturados en días distintos
        dejarían de contarse como duplicados, que es justo lo que hay que ver.
        """
        excluded = {self.label_col, self.split_col}
        return [c for c in self.df.columns if c not in excluded and not c.startswith("__")]

    @cached_property
    def hash_cols(self) -> list[str]:
        """Columnas que definen "la misma fila" para duplicados y conflictos.

        Salen las de rol declaradas (tiempo, IPs): el mismo flujo visto desde
        otro host o en otra hora es un duplicado, y con la IP o la hora en el
        hash nunca se vería. Siguen siendo características para el resto de los
        checks: `shortcut.single_feature` y los de fuga las necesitan.
        """
        return [c for c in self.feature_cols if c not in self.declared_roles]

    @cached_property
    def numeric_cols(self) -> list[str]:
        return [
            c
            for c in self.feature_cols
            if self.df.schema[c].is_numeric()  # type: ignore[union-attr]
        ]

    @cached_property
    def row_hash(self) -> pl.Series:
        """Hash por fila sobre las características (sin etiqueta ni split)."""
        return row_hashes(self.df, self.hash_cols)

    @cached_property
    def full_row_hash(self) -> pl.Series:
        """Hash por fila incluyendo la etiqueta."""
        cols = self.hash_cols + ([self.label_col] if self.label_col else [])
        return row_hashes(self.df, cols)

    @cached_property
    def shared(self) -> dict[str, Any]:
        """Caché para resultados caros que varios checks comparten.

        `cached_property` cubre lo que el contexto sabe calcular solo. Esto
        cubre lo que no: el módulo de envenenamiento arma una matriz de
        características que `poison.loss`, `poison.knn` y `poison.cluster` usan
        por igual, y armarla tres veces sobre millones de filas es el triple
        del costo por el mismo resultado.

        Quien lo llena es el primer check que lo necesita; los demás lo
        encuentran hecho. La clave la define quien la guarda.
        """
        return {}

    def examples_from(self, mask: pl.Series, limit: int = 10) -> list[dict[str, Any]]:
        """Hasta ``limit`` filas de ejemplo para la evidencia de un hallazgo."""
        subset = self.df.filter(mask).head(limit)
        return subset.to_dicts()
