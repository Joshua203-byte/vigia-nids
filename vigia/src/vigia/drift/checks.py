"""Checks de deriva (sección 10).

Los cinco comparan `ctx.df` (el lote nuevo) contra `ctx.reference` (lo que se
usó para entrenar). Ninguno corre en una auditoría normal: sin referencia no
hay nada contra qué comparar.
"""

from __future__ import annotations

from typing import Any

import polars as pl

from vigia.core.context import AuditContext, CheckSkipped
from vigia.core.findings import Finding
from vigia.core.registry import register
from vigia.drift.metrics import (
    PSI_MODERADO,
    PSI_SEVERO,
    js_divergence,
    ks_statistic,
    psi,
)


def _require_reference(ctx: AuditContext) -> pl.DataFrame:
    if ctx.reference is None:
        raise CheckSkipped(
            "requiere un dataset de referencia contra el cual comparar (vigia drift --reference)"
        )
    if ctx.reference.is_empty() or ctx.df.is_empty():
        raise CheckSkipped("la referencia o el lote actual están vacíos")
    return ctx.reference


@register
class SchemaDriftCheck:
    """`drift.schema` — columnas nuevas, faltantes o con otro tipo.

    Va primero porque un cambio de esquema explica cualquier otra deriva y hay
    que arreglarlo antes de mirar distribuciones: si una columna cambió de
    unidad o de tipo, el PSI dirá que hay deriva severa y tendrá razón, pero
    la causa es el sensor, no la red.
    """

    id = "drift.schema"
    name = "Cambio de esquema entre la referencia y el lote actual"
    category = "drift"
    applies_to = {"flows", "tabular"}
    module = "drift"

    def run(self, ctx: AuditContext) -> list[Finding]:
        ref = _require_reference(ctx)

        cols_ref = set(ref.columns)
        cols_act = set(ctx.df.columns)
        faltantes = sorted(cols_ref - cols_act)
        nuevas = sorted(cols_act - cols_ref)

        cambios_tipo = [
            {"columna": c, "antes": str(ref.schema[c]), "ahora": str(ctx.df.schema[c])}
            for c in sorted(cols_ref & cols_act)
            if ref.schema[c] != ctx.df.schema[c]
        ]

        if not faltantes and not nuevas and not cambios_tipo:
            return []

        # Una columna que falta rompe el modelo; una nueva solo se ignora.
        severity = "critical" if faltantes else ("high" if cambios_tipo else "medium")
        partes = []
        if faltantes:
            partes.append(f"{len(faltantes)} columna(s) que el modelo espera ya no están")
        if cambios_tipo:
            partes.append(f"{len(cambios_tipo)} cambiaron de tipo")
        if nuevas:
            partes.append(f"{len(nuevas)} son nuevas")

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title="El esquema del lote no coincide con el de la referencia",
                description=(
                    f"{'; '.join(partes)}. Un cambio de esquema suele ser una "
                    "actualización del sensor o del extractor de flujos, no un cambio "
                    "en la red. Conviene resolverlo antes de mirar la deriva de las "
                    "distribuciones: una columna que cambió de unidad o de tipo hace "
                    "que todo lo demás parezca haber derivado."
                ),
                metric={
                    "n_faltantes": float(len(faltantes)),
                    "n_nuevas": float(len(nuevas)),
                    "n_cambios_tipo": float(len(cambios_tipo)),
                },
                affected_rows=0,
                examples=(
                    [{"falta": c} for c in faltantes[:5]]
                    + [{"nueva": c} for c in nuevas[:5]]
                    + cambios_tipo[:5]
                ),
                recommendation=(
                    "Revisar si cambió la versión del sensor o del extractor. Si las "
                    "columnas faltantes son características del modelo, este no puede "
                    "predecir hasta que se restituyan."
                ),
                auto_fix=None,
            )
        ]


@register
class FeatureDriftCheck:
    """`drift.feature` — la distribución de las características cambió.

    Es la deriva de datos (covariate shift): el tráfico de hoy no se parece al
    de entrenamiento. El modelo sigue funcionando, pero está extrapolando.
    """

    id = "drift.feature"
    name = "Deriva en la distribución de las características"
    category = "drift"
    applies_to = {"flows", "tabular"}
    module = "drift"

    #: Por encima de este PSI se reporta la columna.
    THRESHOLD = PSI_MODERADO
    #: Cuántas columnas derivadas hacen falta para que sea grave: una sola
    #: puede ser un sensor; muchas a la vez es que cambió la red.
    MANY_COLUMNS = 5

    def run(self, ctx: AuditContext) -> list[Finding]:
        ref = _require_reference(ctx)
        umbral = float(ctx.option("psi_threshold", self.THRESHOLD))

        comunes = [c for c in ctx.numeric_cols if c in ref.columns]
        if not comunes:
            raise CheckSkipped("no hay columnas numéricas en común con la referencia")

        derivadas: list[dict[str, Any]] = []
        for col in comunes:
            valor = psi(ref.get_column(col), ctx.df.get_column(col))
            if valor >= umbral:
                derivadas.append(
                    {
                        "columna": col,
                        "psi": round(valor, 4),
                        "ks": round(ks_statistic(ref.get_column(col), ctx.df.get_column(col)), 4),
                    }
                )

        if not derivadas:
            return []

        derivadas.sort(key=lambda d: -float(d["psi"]))
        peor = float(derivadas[0]["psi"])
        severity = "high" if peor >= PSI_SEVERO or len(derivadas) >= self.MANY_COLUMNS else "medium"

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"{len(derivadas)} característica(s) cambiaron de distribución",
                description=(
                    f"El PSI más alto es {peor:.3f} en '{derivadas[0]['columna']}' "
                    f"(umbral: {umbral}). El tráfico del lote ya no se parece al que se "
                    "usó para entrenar, así que el modelo está extrapolando: sus "
                    "métricas de validación describen otro tráfico. "
                    + (
                        "Que sean varias columnas a la vez apunta a un cambio real en "
                        "la red, no a un sensor aislado."
                        if len(derivadas) >= self.MANY_COLUMNS
                        else "Al ser pocas columnas, conviene descartar primero un "
                        "problema del sensor antes de suponer un cambio en la red."
                    )
                ),
                metric={
                    "n_columnas_derivadas": float(len(derivadas)),
                    "psi_maximo": peor,
                    "n_columnas_evaluadas": float(len(comunes)),
                },
                affected_rows=ctx.n_rows,
                examples=derivadas[:10],
                recommendation=(
                    "Mirar las columnas de mayor PSI: si son importantes para el "
                    "modelo, conviene reentrenar con datos recientes. Si no lo son, "
                    "puede alcanzar con vigilarlas."
                ),
                auto_fix=None,
            )
        ]


@register
class PriorDriftCheck:
    """`drift.prior` — cambió la proporción de cada clase.

    Una campaña masiva de escaneo cambia la proporción de ataques sin que
    cambie nada más. El modelo sigue siendo válido, pero su umbral de decisión
    y la carga de alertas que genera, no.
    """

    id = "drift.prior"
    name = "Deriva en la proporción de clases"
    category = "drift"
    applies_to = {"flows", "tabular"}
    module = "drift"

    #: Divergencia de Jensen-Shannon a partir de la cual se reporta.
    THRESHOLD = 0.05

    def run(self, ctx: AuditContext) -> list[Finding]:
        ref = _require_reference(ctx)
        ctx.require("label_col")
        assert ctx.label_col is not None
        if ctx.label_col not in ref.columns:
            raise CheckSkipped(f"la referencia no tiene la columna '{ctx.label_col}'")

        s_ref = ref.get_column(ctx.label_col).cast(pl.Utf8)
        s_act = ctx.df.get_column(ctx.label_col).cast(pl.Utf8)
        divergencia = js_divergence(s_ref, s_act)
        if divergencia < self.THRESHOLD:
            return []

        p_ref = {k: v / s_ref.len() for k, v in dict(s_ref.value_counts().rows()).items()}
        p_act = {k: v / s_act.len() for k, v in dict(s_act.value_counts().rows()).items()}

        cambios = sorted(
            (
                {
                    "clase": str(k),
                    "antes": f"{p_ref.get(k, 0.0):.3%}",
                    "ahora": f"{p_act.get(k, 0.0):.3%}",
                    "_delta": abs(p_act.get(k, 0.0) - p_ref.get(k, 0.0)),
                }
                for k in set(p_ref) | set(p_act)
            ),
            key=lambda d: -float(d["_delta"]),
        )
        nuevas = sorted(set(p_act) - set(p_ref))
        desaparecidas = sorted(set(p_ref) - set(p_act))

        severity = "high" if nuevas or divergencia >= 0.2 else "medium"

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"La proporción de clases cambió (divergencia {divergencia:.3f})",
                description=(
                    "La mezcla de clases del lote no es la de la referencia."
                    + (
                        f" Aparecieron clases que no estaban: {', '.join(map(str, nuevas[:5]))}."
                        " El modelo no puede predecir una clase que nunca vio."
                        if nuevas
                        else ""
                    )
                    + (
                        f" Dejaron de aparecer: {', '.join(map(str, desaparecidas[:5]))}."
                        if desaparecidas
                        else ""
                    )
                    + " Un cambio de proporción no invalida al modelo, pero sí a su "
                    "umbral de decisión y a la carga de alertas que produce."
                ),
                metric={
                    "js_divergence": divergencia,
                    "n_clases_nuevas": float(len(nuevas)),
                    "n_clases_desaparecidas": float(len(desaparecidas)),
                },
                affected_rows=ctx.n_rows,
                examples=[{k: v for k, v in c.items() if k != "_delta"} for c in cambios[:10]],
                recommendation=(
                    "Si aparecieron clases nuevas, hay que reentrenar. Si solo cambió "
                    "la proporción, recalibrar el umbral suele alcanzar."
                ),
                auto_fix=None,
            )
        ]


@register
class CovariateDriftCheck:
    """`drift.covariate` — los dos conjuntos son distinguibles entre sí.

    Se mide con validación adversaria: se entrena un clasificador que intenta
    distinguir la referencia del lote actual. Si lo logra, los dos conjuntos
    son distinguibles, y un modelo entrenado en uno no describe al otro.

    Antes de la 1.0.0 este check se llamaba `drift.concept`, pero no mira la
    etiqueta: mide el cambio en la distribución conjunta de las
    características (covariate shift), no en su relación con la etiqueta. Con
    P(X) igual y la etiqueta invertida daba AUC 0,5 y el semáforo verde
    (AUDITORIA-1.0.md, SCI-03). La deriva de concepto la mide ahora
    `ConceptDriftCheck`.
    """

    id = "drift.covariate"
    name = "Los dos conjuntos son distinguibles entre sí"
    category = "drift"
    applies_to = {"flows", "tabular"}
    module = "drift"

    #: AUC a partir del cual los conjuntos se consideran distinguibles. 0,5 es
    #: no poder distinguirlos en absoluto, que es lo esperable sin deriva.
    THRESHOLD = 0.75
    MAX_ROWS = 50_000

    def run(self, ctx: AuditContext) -> list[Finding]:
        ref = _require_reference(ctx)
        try:
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.metrics import roc_auc_score
            from sklearn.model_selection import cross_val_predict
        except ImportError as exc:  # pragma: no cover
            raise CheckSkipped("requiere scikit-learn: pip install 'vigia-nids[ml]'") from exc

        comunes = [c for c in ctx.numeric_cols if c in ref.columns]
        if len(comunes) < 2:
            raise CheckSkipped("hacen falta al menos 2 columnas numéricas en común")

        def _matriz(df: pl.DataFrame, n: int) -> Any:
            sub = df.select(comunes)
            if sub.height > n:
                sub = sub.sample(n=n, seed=ctx.seed)
            return (
                sub.with_columns(
                    [
                        pl.when(pl.col(c).is_finite()).then(pl.col(c)).otherwise(None).alias(c)
                        for c in comunes
                        if sub.schema[c].is_float()
                    ]
                )
                .fill_null(0)
                .to_numpy()
                .astype("float64")
            )

        n = min(self.MAX_ROWS, ref.height, ctx.n_rows)
        if n < 50:
            raise CheckSkipped("hacen falta al menos 50 filas de cada lado")

        x_ref, x_act = _matriz(ref, n), _matriz(ctx.df, n)
        x = np.vstack([x_ref, x_act])
        y = np.concatenate([np.zeros(len(x_ref)), np.ones(len(x_act))])

        modelo = RandomForestClassifier(
            n_estimators=50, max_depth=8, random_state=ctx.seed, n_jobs=1
        )
        # Un fallo del entrenamiento es un error (va a `errors`, semaforo rojo), no un
        # "no aplica" con el texto de la excepcion (VERIFICACION-1.0.md, VER-05).
        probs = cross_val_predict(modelo, x, y, cv=3, method="predict_proba", n_jobs=1)
        auc = float(roc_auc_score(y, probs[:, 1]))

        if auc < self.THRESHOLD:
            return []

        # Qué columnas permiten distinguirlos: son las que más derivaron.
        modelo.fit(x, y)
        importancias = sorted(
            zip(comunes, modelo.feature_importances_, strict=True),
            key=lambda kv: -kv[1],
        )

        severity = "critical" if auc >= 0.9 else "high"

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=f"Un clasificador distingue los dos conjuntos con AUC {auc:.3f}",
                description=(
                    "Se entrenó un modelo para decidir si una fila viene de la "
                    f"referencia o del lote nuevo, y lo logra con AUC {auc:.3f}. Sin "
                    "deriva debería rondar 0,5, o sea no poder distinguirlos. "
                    "Que sean tan separables significa que el modelo de producción "
                    "está viendo un tráfico distinto del que aprendió, y sus métricas "
                    "de validación ya no lo describen."
                ),
                metric={
                    "auc": auc,
                    "n_filas_por_lado": float(n),
                    "n_columnas": float(len(comunes)),
                },
                affected_rows=ctx.n_rows,
                examples=[
                    {"columna": c, "aporta_a_distinguir": f"{imp:.3f}"}
                    for c, imp in importancias[:10]
                ],
                recommendation=(
                    "Reentrenar con datos recientes. Las columnas de arriba son las "
                    "que más cambiaron: si alguna no debería haber cambiado, revisar "
                    "primero el sensor."
                ),
                auto_fix=None,
            )
        ]


@register
class ConceptDriftCheck:
    """`drift.concept` — cambió la relación entre características y etiqueta.

    Es la deriva más grave y la más difícil de ver: las distribuciones pueden
    no haberse movido, pero lo que antes significaba "ataque" ahora significa
    otra cosa. Un malware nuevo que se comporta como tráfico normal.

    Se mide con la etiqueta, que es la única forma: se entrena un modelo con
    la referencia y se compara, **clase por clase**, cuánto reconoce dentro de
    la referencia (validación cruzada) con cuánto reconoce en el lote. Si cae,
    la relación que aprendió ya no vale. Sin etiqueta en el lote no hay forma
    de medirlo y el check se salta diciéndolo, en vez de responder con otra
    cosa (eso hacía la versión anterior, que ahora es `drift.covariate`).

    Tres cuidados, cada uno por una falla medida en la verificación
    (`VERIFICACION-1.0.md`):

    * Se comparan solo las clases que están en el lote con filas suficientes, y
      con el mismo promedio de recall en los dos lados. Antes se comparaba la
      exactitud balanceada de la referencia (todas las clases) con la del lote:
      con un lote de una sola clase eso es el recall de esa clase contra el
      promedio de todas, y daba crítico sin que nada hubiera cambiado (VER-03).
      Un lote de una sola clase sí se puede evaluar: es justo el caso "llegan
      ataques que el modelo ya no reconoce".
    * La validación cruzada agrupa las filas idénticas: las copias de una misma
      fila no quedan repartidas entre entrenamiento y prueba, que inflaba lo
      que la referencia "sabía" y hacía que cualquier lote pareciera derivar
      (VER-04). El filtro de habilidad usa esa exactitud corregida.
    * Las filas del lote idénticas a una de la referencia se excluyen: el modelo
      las memorizó y aciertan sin decir nada de la relación, lo que podía
      ocultar deriva real. La cantidad va en la métrica.
    """

    id = "drift.concept"
    name = "Cambió la relación entre características y etiqueta"
    category = "drift"
    applies_to = {"flows", "tabular"}
    module = "drift"

    #: Caída del recall medio (en puntos de proporción) a partir de la cual se
    #: reporta. Con dos muestras del mismo generador la diferencia es ruido de
    #: muestreo de pocas centésimas.
    THRESHOLD = 0.10
    #: A partir de esta caída es crítica: el modelo perdió una cuarta parte de
    #: lo que sabía reconocer.
    CRITICAL = 0.25
    #: Además de pasar el umbral, la caída tiene que superar este múltiplo de su
    #: error estándar de muestreo: con pocas filas por clase, 0,10 es ruido. 4 y no 3
    #: porque el error estándar binomial subestima la variación real (el modelo de
    #: la referencia también varía): con 3, un lote de 240 ataques de la misma
    #: distribución dio alto en 1 de 30 sorteos.
    Z = 4.0
    #: Cuánto tiene que superar al azar (1/k) el modelo dentro de la
    #: referencia: si ahí ya no aprende la etiqueta, una "caída" no dice nada.
    MIN_SKILL = 0.10
    MAX_ROWS = 50_000
    MIN_ROWS = 50
    #: Filas mínimas de una clase, en la referencia y en el lote, para compararla.
    MIN_ROWS_CLASE = 30

    def run(self, ctx: AuditContext) -> list[Finding]:
        ref = _require_reference(ctx)
        try:
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.metrics import balanced_accuracy_score
            from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
        except ImportError as exc:  # pragma: no cover
            raise CheckSkipped("requiere scikit-learn: pip install 'vigia-nids[ml]'") from exc

        label = ctx.label_col
        if label is None or label not in ctx.df.columns:
            raise CheckSkipped(
                "el lote no trae etiqueta: sin ella no se puede medir si cambió la relación "
                "entre características y etiqueta (drift.covariate y drift.feature sí corren)"
            )
        if label not in ref.columns:
            raise CheckSkipped(f"la referencia no tiene la columna '{label}'")

        comunes = [c for c in ctx.numeric_cols if c in ref.columns]
        if not comunes:
            raise CheckSkipped("no hay columnas numéricas en común con la referencia")

        def _xy(df: pl.DataFrame) -> tuple[Any, Any]:
            sub = df.select([*comunes, label]).filter(pl.col(label).is_not_null())
            if sub.height > self.MAX_ROWS:
                sub = sub.sample(n=self.MAX_ROWS, seed=ctx.seed)
            x = (
                sub.select(comunes)
                .with_columns(
                    [
                        pl.when(pl.col(c).is_finite()).then(pl.col(c)).otherwise(None).alias(c)
                        for c in comunes
                        if sub.schema[c].is_float()
                    ]
                )
                .fill_null(0)
                .to_numpy()
                .astype("float64")
            )
            return x, np.array(sub.get_column(label).cast(pl.Utf8).to_list())

        x_ref, y_ref = _xy(ref)
        x_act, y_act = _xy(ctx.df)
        clases = sorted(set(y_ref.tolist()))
        if len(clases) < 2:
            raise CheckSkipped("la referencia tiene una sola clase: no hay relación que medir")
        # Una clase que la referencia nunca vio no es una caída del modelo:
        # es `drift.prior`, que ya la reporta como clase nueva.
        conocidas = np.isin(y_act, clases)
        x_act, y_act = x_act[conocidas], y_act[conocidas]
        if len(y_ref) < self.MIN_ROWS:
            raise CheckSkipped(
                f"hacen falta al menos {self.MIN_ROWS} filas etiquetadas en la referencia"
            )

        # Hash de cada fila de características: agrupa las copias para la
        # validación cruzada y detecta las filas del lote que ya estaban en la
        # referencia (VER-04 y el caso inverso).
        h_ref = pl.from_numpy(x_ref, orient="row").hash_rows(seed=0).to_numpy()
        h_act = pl.from_numpy(x_act, orient="row").hash_rows(seed=0).to_numpy()
        repetidas = np.isin(h_act, h_ref)
        n_repetidas = int(repetidas.sum())
        x_act, y_act = x_act[~repetidas], y_act[~repetidas]

        comparables = [
            c
            for c in clases
            if int((y_act == c).sum()) >= self.MIN_ROWS_CLASE
            and int((y_ref == c).sum()) >= self.MIN_ROWS_CLASE
        ]
        if not comparables:
            if len(y_act) == 0 and n_repetidas:
                raise CheckSkipped(
                    "todas las filas etiquetadas del lote están también en la referencia: "
                    "el modelo ya las vio y no hay nada nuevo que medir"
                )
            raise CheckSkipped(
                f"ninguna clase tiene al menos {self.MIN_ROWS_CLASE} filas en el lote y en la "
                f"referencia (excluidas {n_repetidas} del lote que ya estaban en la referencia)"
            )

        modelo = RandomForestClassifier(
            n_estimators=50, max_depth=8, random_state=ctx.seed, n_jobs=1
        )
        # Con menos filas distintas que pliegues la validacion cruzada no se arma:
        # eso si es "no aplica". Cualquier otro fallo es un error, no un salto con el
        # texto de la excepcion (VERIFICACION-1.0.md, VER-05).
        if len(np.unique(h_ref)) < 3:
            raise CheckSkipped("la referencia tiene menos de 3 filas distintas")
        # Estratificada y por grupos: las copias de una fila van juntas.
        cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=ctx.seed)
        pred_ref = cross_val_predict(modelo, x_ref, y_ref, cv=cv, groups=h_ref, n_jobs=1)
        modelo.fit(x_ref, y_ref)
        pred_act = modelo.predict(x_act)

        habilidad = float(balanced_accuracy_score(y_ref, pred_ref))
        if habilidad < 1.0 / len(clases) + self.MIN_SKILL:
            raise CheckSkipped(
                f"el modelo no aprende la etiqueta ni dentro de la referencia (exactitud "
                f"balanceada {habilidad:.3f}): una caída no diría nada"
            )

        por_clase = []
        varianza = 0.0
        for c in comparables:
            n_r, n_a = int((y_ref == c).sum()), int((y_act == c).sum())
            r_ref = float((pred_ref[y_ref == c] == c).mean())
            r_act = float((pred_act[y_act == c] == c).mean())
            # Varianza binomial con un ajuste que evita el cero cuando el recall es 0 o 1.
            for r, n in ((r_ref, n_r), (r_act, n_a)):
                p = (r * n + 0.5) / (n + 1)
                varianza += p * (1 - p) / n
            por_clase.append((c, r_ref, r_act))
        k = len(comparables)
        en_ref = sum(t[1] for t in por_clase) / k
        en_lote = sum(t[2] for t in por_clase) / k
        caida = en_ref - en_lote
        error_estandar = varianza**0.5 / k
        if caida < self.THRESHOLD or caida < self.Z * error_estandar:
            return []

        por_clase.sort(key=lambda t: -(t[1] - t[2]))
        nombres = ", ".join(str(t[0]) for t in por_clase[:3])
        severity = "critical" if caida >= self.CRITICAL else "high"

        return [
            Finding(
                check_id=self.id,
                severity=severity,  # type: ignore[arg-type]
                title=(
                    f"El modelo de la referencia pierde {caida:.1%} de recall en {nombres} "
                    "sobre el lote"
                ),
                description=(
                    f"Entrenado con la referencia, el modelo reconoce en promedio "
                    f"{en_ref:.3f} de las filas de {k} clase(s) dentro de ella (validación "
                    f"cruzada, con las copias de una fila juntas) y {en_lote:.3f} en el "
                    f"lote. Clases comparadas: {', '.join(str(t[0]) for t in por_clase)}. "
                    "La relación entre las características y la etiqueta que aprendió ya "
                    "no explica los datos nuevos. Si `drift.covariate` o `drift.feature` también "
                    "reportan, parte de la caída puede venir de que el tráfico cambió y el "
                    "modelo extrapola; en cualquier caso, ya no rinde lo que rendía."
                ),
                metric={
                    "recall_medio_referencia": en_ref,
                    "recall_medio_lote": en_lote,
                    "caida": caida,
                    "error_estandar": error_estandar,
                    "n_clases_comparadas": float(k),
                    "n_filas_lote": float(len(y_act)),
                    "n_filas_repetidas_excluidas": float(n_repetidas),
                },
                affected_rows=ctx.n_rows,
                examples=[
                    {"clase": c, "recall_referencia": f"{a:.3f}", "recall_lote": f"{b:.3f}"}
                    for c, a, b in por_clase[:10]
                ],
                recommendation=(
                    "Reentrenar con datos recientes etiquetados. Las clases de arriba son "
                    "las que más cambiaron: revisar si su etiquetado o su comportamiento "
                    "es distinto del que había en la referencia."
                ),
                auto_fix=None,
            )
        ]
