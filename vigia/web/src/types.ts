// Tipos que reflejan el formato del reporte JSON de Vigía.
// Ver docs/USO.md, sección "Formato del reporte JSON", y
// src/vigia/core/findings.py (Report.to_dict / Finding.to_dict) como fuente
// de verdad. Cualquier cambio ahí debe reflejarse acá.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type TrafficLightColor = "rojo" | "amarillo" | "verde" | "gris";

export interface Finding {
  check_id: string;
  severity: Severity;
  title: string;
  description: string;
  metric: Record<string, number>;
  affected_rows: number;
  examples: Record<string, unknown>[];
  recommendation: string;
  auto_fix: string | null;
}

export interface ReportSummary {
  traffic_light: TrafficLightColor;
  counts: Record<Severity, number>;
  total: number;
  n_skipped: number;
  n_errors: number;
}

export interface ReportDataset {
  path: string;
  sha256: string;
  n_rows: number;
  n_cols: number;
}

export interface ReportRun {
  vigia_version: string;
  seed: number;
}

export interface Report {
  schema_version: string;
  dataset: ReportDataset;
  run: ReportRun;
  summary: ReportSummary;
  findings: Finding[];
  /** Checks que no aplicaban a este dataset (falta una columna, una dependencia). */
  skipped: Record<string, string>;
  /** Checks que fallaron por un error interno de Vigía: no dicen nada del dataset. */
  errors: Record<string, string>;
}

export type JobKind = "audit" | "poison" | "drift";
export type JobStatus = "pendiente" | "corriendo" | "terminado" | "fallido";

export interface JobStatusResponse {
  job_id: string;
  kind: JobKind;
  status: JobStatus;
  result: Report | null;
  error: string | null;
}

export interface DatasetUploadResponse {
  dataset_id: string;
  n_rows: number;
  n_cols: number;
}

export interface JobCreatedResponse {
  job_id: string;
}

export interface CheckInfo {
  id: string;
  name: string;
  category: string;
  module: string;
}
