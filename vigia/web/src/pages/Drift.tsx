import { useEffect, useRef, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ApiError, getDriftStatus, launchDrift, uploadDataset } from "../api";
import { Findings } from "../components/Findings";
import { ErrorChecks } from "../components/ErrorChecks";
import { SkippedChecks } from "../components/SkippedChecks";
import { TrafficLight } from "../components/TrafficLight";
import type { JobStatusResponse } from "../types";

const POLL_INTERVAL_MS = 1500;
const PSI_THRESHOLD_DEFAULT = 0.2;

function FileField({
  label,
  file,
  onChange,
}: {
  label: string;
  file: File | null;
  onChange: (f: File | null) => void;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      <input
        type="file"
        accept=".csv,.parquet,.pq"
        aria-label={label}
        onChange={(e) => onChange(e.target.files?.[0] ?? null)}
      />
      {file && (
        <p className="cid">
          {file.name} ({(file.size / (1024 * 1024)).toFixed(2)} MB)
        </p>
      )}
    </div>
  );
}

/** Extrae PSI por columna de los hallazgos de deriva.
 *
 * `drift.feature` (src/vigia/drift/checks.py) reporta un único hallazgo
 * agregado para todas las columnas que superan el umbral, y el detalle por
 * columna ({columna, psi, ks}) va en `examples`, no en `metric` (que solo
 * trae el resumen: cuántas columnas derivaron y el PSI máximo). Point de
 * fuga si el check cambia de forma; se lee de forma defensiva. */
function psiSeries(report: NonNullable<JobStatusResponse["result"]>) {
  const rows: { column: string; psi: number; severity: string }[] = [];
  for (const f of report.findings) {
    for (const ex of f.examples) {
      const column = ex["columna"];
      const psi = ex["psi"];
      if (typeof column === "string" && typeof psi === "number") {
        rows.push({ column, psi, severity: f.severity });
      }
    }
  }
  return rows.sort((a, b) => b.psi - a.psi);
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function DriftPage() {
  const [batchFile, setBatchFile] = useState<File | null>(null);
  const [referenceFile, setReferenceFile] = useState<File | null>(null);
  const [labelCol, setLabelCol] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;

    async function poll() {
      try {
        const status = await getDriftStatus(jobId!);
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

  async function handleSubmit() {
    if (!batchFile || !referenceFile) return;
    setBusy(true);
    setError(null);
    setJob(null);
    setJobId(null);
    try {
      setStage("Subiendo el lote nuevo...");
      const batch = await uploadDataset(batchFile);

      setStage("Subiendo la referencia...");
      const reference = await uploadDataset(referenceFile);

      setStage("Lanzando comparación de deriva...");
      const created = await launchDrift({
        dataset_id: batch.dataset_id,
        reference_id: reference.dataset_id,
        label_col: labelCol.trim() || undefined,
      });

      setJobId(created.job_id);
    } catch (err) {
      setError(err instanceof ApiError ? `${err.message} (HTTP ${err.status})` : String(err));
    } finally {
      setBusy(false);
      setStage(null);
    }
  }

  const isLoading = jobId && (!job || job.status === "pendiente" || job.status === "corriendo");
  const report = job?.status === "terminado" ? job.result : null;
  const series = report ? psiSeries(report) : [];

  return (
    <div>
      <h1>Deriva</h1>
      <p className="sub">
        Compará un lote nuevo contra el dataset de referencia (con el que se
        entrenó) para ver si la distribución de las columnas cambió lo suficiente
        como para justificar un reentrenamiento.
      </p>

      <div className="card">
        <FileField label="Lote nuevo" file={batchFile} onChange={setBatchFile} />
        <FileField label="Referencia (dataset de entrenamiento)" file={referenceFile} onChange={setReferenceFile} />
        <div className="field">
          <label htmlFor="drift-label-col">Columna de etiqueta (opcional)</label>
          <input
            id="drift-label-col"
            type="text"
            value={labelCol}
            onChange={(e) => setLabelCol(e.target.value)}
            placeholder='ej. "Label"'
          />
        </div>
        <button className="btn" disabled={!batchFile || !referenceFile || busy} onClick={handleSubmit}>
          {busy && <span className="spinner" aria-hidden="true" />}
          {busy ? (stage ?? "Procesando...") : "Comparar"}
        </button>
      </div>

      {error && (
        <div className="error-box" role="alert">
          <strong>Error:</strong> {error}
        </div>
      )}

      <div aria-live="polite" aria-atomic="true">
        {isLoading && (
          <div className="card result-loading" style={{ marginTop: 20 }}>
            <span className="spinner" aria-hidden="true" />
            <span>Comparando distribuciones ({job?.status ?? "pendiente"})...</span>
          </div>
        )}

        {job?.status === "fallido" && (
          <div className="error-box" role="alert">
            <strong>La comparación de deriva falló.</strong>
            <p>{job.error ?? "No se recibió un mensaje de error del servidor."}</p>
          </div>
        )}

        {report && (
          <div style={{ marginTop: 24 }}>
            <TrafficLight color={report.summary.traffic_light} />

            <ErrorChecks errors={report.errors} />
            <SkippedChecks skipped={report.skipped} />

            {series.length > 0 && (
              <>
                <h2>PSI por columna</h2>
                <p className="sub">
                  Population Stability Index. Por encima de {PSI_THRESHOLD_DEFAULT} suele
                  considerarse deriva relevante (línea punteada).
                </p>
                <div className="card" style={{ height: Math.max(220, series.length * 34) }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={series} layout="vertical" margin={{ left: 24 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
                      <XAxis type="number" stroke="var(--muted)" />
                      <YAxis
                        type="category"
                        dataKey="column"
                        width={140}
                        stroke="var(--muted)"
                        tick={{ fill: "var(--fg)", fontSize: 12 }}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "var(--card)",
                          border: "1px solid var(--line)",
                          color: "var(--fg)",
                        }}
                        formatter={(value) => (typeof value === "number" ? value.toFixed(3) : value)}
                      />
                      <ReferenceLine x={PSI_THRESHOLD_DEFAULT} stroke="var(--muted)" strokeDasharray="4 4" />
                      <Bar dataKey="psi" isAnimationActive={false}>
                        {series.map((s, i) => (
                          <Cell key={i} fill={SEVERITY_COLOR[s.severity] ?? "var(--sev-info)"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}

            <h2>Hallazgos de deriva ({report.summary.total})</h2>
            <Findings findings={report.findings} />
          </div>
        )}
      </div>
    </div>
  );
}
