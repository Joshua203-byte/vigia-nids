import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError, getAuditStatus, recallAuditColumns } from "../api";
import type { AuditColumns } from "../api";
import type { Finding, JobStatusResponse } from "../types";

const POLL_INTERVAL_MS = 1500;

// Descripciones de las correcciones conocidas (docs/USO.md, "vigia fix").
// La API no expone un catálogo de correcciones (no existe un
// `GET /api/v1/fixes`), así que esto es la única fuente de "qué hace cada
// una" disponible del lado del cliente sin inventar un endpoint. Si aparece
// un auto_fix que no está acá, se muestra igual con una descripción genérica
// en vez de ocultarlo.
const FIX_DESCRIPTIONS: Record<string, string> = {
  drop_duplicates: "Elimina filas duplicadas (exactas o repetidas entre splits).",
  drop_constant: "Elimina columnas constantes que no aportan información al modelo.",
  drop_identifiers: "Elimina columnas identificadoras (IPs, puertos, timestamps) que causan atajos.",
  temporal_split: "Reconstruye el split train/test por corte temporal en vez de al azar.",
  quarantine_noise: "Aparta en cuarentena las filas con ruido de etiqueta sospechoso, sin borrarlas.",
};

function describeFix(fixId: string): string {
  return FIX_DESCRIPTIONS[fixId] ?? "Corrección disponible vía la CLI (vigia fix).";
}

// Opciones de `vigia fix` que corresponden a las columnas con que se lanzó la
// auditoría: sin ellas la CLI las vuelve a detectar por nombre y puede elegir
// otras que las que se auditaron.
const COLUMN_FLAGS: [keyof AuditColumns, string][] = [
  ["label_col", "--label-col"],
  ["split_col", "--split-col"],
  ["time_col", "--time-col"],
  ["src_ip_col", "--src-ip-col"],
  ["dst_ip_col", "--dst-ip-col"],
];

// El servidor guarda el archivo con un id opaco (`dataset:<id>`): esa ruta no
// existe en la máquina de quien corre la CLI, así que va un marcador
// `<archivo>` para que la persona ponga el suyo (AUDITORIA-1.0.md, COR-10).
function fixCommand(fixIds: string[], columns: AuditColumns): string {
  const lines = ["vigia fix <archivo>", `  --apply ${fixIds.join(",")}`];
  for (const [key, flag] of COLUMN_FLAGS) {
    const value = columns[key];
    if (value) lines.push(`  ${flag} "${value.replace(/(["\\$`])/g, "\\$1")}"`);
  }
  lines.push("  --out <archivo>_corregido.parquet");
  return lines.join(" \\\n");
}

export function FixPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;

    async function poll() {
      try {
        const status = await getAuditStatus(jobId!);
        if (cancelled) return;
        setJob(status);
        if (status.status === "pendiente" || status.status === "corriendo") {
          timerRef.current = window.setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? `${err.message} (HTTP ${err.status})` : String(err));
      }
    }

    poll();
    return () => {
      cancelled = true;
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [jobId]);

  if (!jobId) return <p>Falta el identificador del trabajo.</p>;
  if (error) {
    return (
      <div className="error-box" role="alert">
        <strong>No se pudo consultar el trabajo:</strong> {error}
      </div>
    );
  }

  const report = job?.status === "terminado" ? job.result : null;
  const findingsWithFix: Finding[] = report ? report.findings.filter((f) => f.auto_fix) : [];
  const uniqueFixIds = [...new Set(findingsWithFix.map((f) => f.auto_fix as string))];

  return (
    <div>
      <h1>Corregir</h1>
      <p className="sub">
        Esta pantalla muestra qué correcciones aplicarían según los hallazgos de la
        auditoría. La API todavía no tiene un endpoint para aplicar correcciones —
        eso hoy se hace con la CLI (<code>vigia fix</code>). Acá no hay ningún botón
        que finja hacerlo por vos.
      </p>

      {!report && (
        <div className="card">
          <span className="spinner" aria-hidden="true" /> Esperando el resultado de la
          auditoría ({job?.status ?? "pendiente"})...
        </div>
      )}

      {report && findingsWithFix.length === 0 && (
        <div className="empty">
          Ningún hallazgo de esta auditoría tiene una corrección automática sugerida.
        </div>
      )}

      {report && findingsWithFix.length > 0 && (
        <>
          <h2>Correcciones sugeridas</h2>
          <ul className="fix-list">
            {findingsWithFix.map((f, i) => (
              <li key={`${i}-${f.check_id}`} className="card fix-item">
                <p className="cid">{f.check_id}</p>
                <p>
                  <strong>{f.title}</strong>
                </p>
                <p>
                  Corrección sugerida: <code>{f.auto_fix}</code> — {describeFix(f.auto_fix as string)}
                </p>
              </li>
            ))}
          </ul>

          <h2>Aplicarlas por la CLI</h2>
          <p className="sub">
            Las correcciones se aplican en cadena, cada una sobre el resultado de la
            anterior. El archivo original nunca se modifica. Reemplazá{" "}
            <code>&lt;archivo&gt;</code> por la ruta del dataset en tu máquina: el
            servidor guarda el que subiste con un identificador interno.
          </p>
          <pre>
            <code>
              {fixCommand(uniqueFixIds, recallAuditColumns(jobId))}
            </code>
          </pre>
        </>
      )}
    </div>
  );
}
