import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, getAuditStatus, openAuditReportHtml } from "../api";
import { Findings } from "../components/Findings";
import { ErrorChecks } from "../components/ErrorChecks";
import { SkippedChecks } from "../components/SkippedChecks";
import { TrafficLight } from "../components/TrafficLight";
import type { JobStatusResponse } from "../types";

const POLL_INTERVAL_MS = 1500;

const STATUS_LABEL: Record<string, string> = {
  pendiente: "En cola, esperando para empezar...",
  corriendo: "Auditando el dataset...",
  terminado: "Terminado",
  fallido: "Falló",
};

export function ResultPage() {
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
        if (err instanceof ApiError) {
          setError(`${err.message} (HTTP ${err.status})`);
        } else {
          setError(err instanceof Error ? err.message : "Error desconocido");
        }
      }
    }

    poll();
    return () => {
      cancelled = true;
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [jobId]);

  if (!jobId) {
    return <p>Falta el identificador del trabajo.</p>;
  }

  if (error) {
    return (
      <div className="error-box" role="alert">
        <strong>No se pudo consultar el trabajo:</strong> {error}
      </div>
    );
  }

  const isLoading = !job || job.status === "pendiente" || job.status === "corriendo";

  return (
    <div>
      <h1>Resultado de la auditoría</h1>
      <p className="sub cid">job_id: {jobId}</p>

      {/* aria-live: un lector de pantalla anuncia el cambio de estado sin
          que el usuario tenga que estar mirando la pantalla mientras se hace
          polling (docs/PLAN.md, 3.4). */}
      <div aria-live="polite" aria-atomic="true">
        {isLoading && (
          <div className="card result-loading">
            <span className="spinner" aria-hidden="true" />
            <span>{STATUS_LABEL[job?.status ?? "pendiente"]}</span>
          </div>
        )}

        {job?.status === "fallido" && (
          <div className="error-box" role="alert">
            <strong>La auditoría falló.</strong>
            <p>{job.error ?? "No se recibió un mensaje de error del servidor."}</p>
          </div>
        )}

        {job?.status === "terminado" && job.result && <ResultDetail jobId={jobId} report={job.result} />}
      </div>
    </div>
  );
}

function ResultDetail({ jobId, report }: { jobId: string; report: NonNullable<JobStatusResponse["result"]> }) {
  const { summary, findings, skipped, errors, dataset } = report;
  const [openingReport, setOpeningReport] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  return (
    <div className="result-detail">
      {/* 1. ¿Mi dataset está bien? El semáforo, grande, arriba de todo. */}
      <TrafficLight color={summary.traffic_light} />

      <ul className="result-counts">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
          <li key={sev}>
            {sev}
            <b>{summary.counts[sev]}</b>
          </li>
        ))}
      </ul>

      {/* El gris tiene que ser tan visible como el rojo: si hay checks
          saltados, se muestran siempre, inmediatamente después del semáforo,
          nunca escondidos detrás de un toggle. */}
      <ErrorChecks errors={errors} />
      <SkippedChecks skipped={skipped} />

      {/* 2. ¿Qué está mal? Hallazgos por severidad. */}
      <h2>Hallazgos ({summary.total})</h2>
      <Findings findings={findings} />

      {/* 3. ¿Qué hago? Enlace a la pantalla de Corregir. */}
      {findings.some((f) => f.auto_fix) && (
        <div className="card" style={{ marginTop: 20 }}>
          <p style={{ margin: 0 }}>
            Hay hallazgos con una corrección sugerida.{" "}
            <Link to={`/corregir/${jobId}`}>Ver qué se puede corregir →</Link>
          </p>
        </div>
      )}

      <h2>Detalle técnico</h2>
      <div className="card">
        <dl className="meta-list">
          <dt>Archivo</dt>
          <dd className="cid">{dataset.path}</dd>
          <dt>Filas × columnas</dt>
          <dd>
            {dataset.n_rows.toLocaleString("es-AR")} × {dataset.n_cols.toLocaleString("es-AR")}
          </dd>
          <dt>SHA-256</dt>
          <dd className="cid">{dataset.sha256}</dd>
        </dl>
        <p>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={openingReport}
            onClick={() => {
              setReportError(null);
              setOpeningReport(true);
              openAuditReportHtml(jobId)
                .catch((err: unknown) =>
                  setReportError(
                    err instanceof ApiError ? `${err.message} (HTTP ${err.status})` : String(err),
                  ),
                )
                .finally(() => setOpeningReport(false));
            }}
          >
            Ver el reporte HTML completo (generado por el servidor) →
          </button>
        </p>
        {reportError && (
          <div className="error-box" role="alert">
            <strong>No se pudo abrir el reporte:</strong> {reportError}
          </div>
        )}
      </div>
    </div>
  );
}
