// Cliente HTTP mínimo para la API REST de Vigía (docs/USO.md, "API REST").
// Sin librería aparte (axios, etc.): son ocho endpoints y `fetch` alcanza.

import type {
  CheckInfo,
  DatasetUploadResponse,
  JobCreatedResponse,
  JobStatusResponse,
} from "./types";

// En desarrollo, Vite expone las variables que empiezan con VITE_ vía
// import.meta.env. Sin configurar nada, apunta al puerto por defecto de
// `uvicorn vigia.api.app:app --port 8000`. En producción (Docker, un solo
// contenedor) el frontend se sirve desde el mismo origen que la API, así que
// una cadena vacía (rutas relativas) funciona igual de bien.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

// Clave de API opcional (docs/USO.md, "Autenticación"): en desarrollo la API
// normalmente corre sin VIGIA_API_KEY seteada, así que esto puede quedar
// vacío. Si el servidor exige la clave, el usuario la pega en el campo de la
// barra (ver ApiKeyField); queda solo en memoria, nunca en el build.
//
// No existe una variable VITE_API_KEY a propósito: Vite incrusta en el
// JavaScript que se sirve todo lo que empieza con VITE_, así que cualquiera que
// abriera el panel habría podido leer la clave en el bundle (AUDITORIA-1.0.md,
// SEC-08).
let apiKeyOverride: string | null = null;

export function setApiKey(key: string | null): void {
  apiKeyOverride = key && key.trim() !== "" ? key.trim() : null;
}

export function getApiKey(): string | null {
  return apiKeyOverride;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function headers(extra?: Record<string, string>): HeadersInit {
  const key = getApiKey();
  return {
    ...(key ? { "X-API-Key": key } : {}),
    ...extra,
  };
}

async function parseErrorDetail(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (body.detail) return JSON.stringify(body.detail);
  } catch {
    // el cuerpo no era JSON; seguimos con el texto de estado
  }
  return res.statusText || `error HTTP ${res.status}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...headers(), ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    throw new ApiError(res.status, await parseErrorDetail(res));
  }
  return (await res.json()) as T;
}

export async function uploadDataset(file: File): Promise<DatasetUploadResponse> {
  const form = new FormData();
  form.append("file", file);
  return request<DatasetUploadResponse>("/api/v1/datasets", {
    method: "POST",
    body: form,
  });
}

export interface LaunchAuditOptions {
  dataset_id: string;
  label_col?: string;
  split_col?: string;
  time_col?: string;
  src_ip_col?: string;
  dst_ip_col?: string;
}

export async function launchAudit(opts: LaunchAuditOptions): Promise<JobCreatedResponse> {
  const job = await request<JobCreatedResponse>("/api/v1/audits", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts),
  });
  rememberAuditColumns(job.job_id, opts);
  return job;
}

// El reporte no dice con qué columnas se lanzó la auditoría, y la pantalla de
// Corregir las necesita para armar el comando de la CLI (AUDITORIA-1.0.md,
// COR-10). Se guardan en sessionStorage, que puede no estar disponible (modo
// privado, almacenamiento bloqueado): sin él, el comando sale sin columnas.
const COLUMNS_KEY = "vigia:audit-columns:";

export type AuditColumns = Pick<
  LaunchAuditOptions,
  "label_col" | "split_col" | "time_col" | "src_ip_col" | "dst_ip_col"
>;

function rememberAuditColumns(jobId: string, opts: LaunchAuditOptions): void {
  const { label_col, split_col, time_col, src_ip_col, dst_ip_col } = opts;
  try {
    sessionStorage.setItem(
      COLUMNS_KEY + jobId,
      JSON.stringify({ label_col, split_col, time_col, src_ip_col, dst_ip_col }),
    );
  } catch {
    // sin almacenamiento: el comando de Corregir saldrá sin columnas
  }
}

export function recallAuditColumns(jobId: string): AuditColumns {
  try {
    const raw = sessionStorage.getItem(COLUMNS_KEY + jobId);
    return raw ? (JSON.parse(raw) as AuditColumns) : {};
  } catch {
    return {};
  }
}

export async function getAuditStatus(jobId: string): Promise<JobStatusResponse> {
  return request<JobStatusResponse>(`/api/v1/audits/${encodeURIComponent(jobId)}`);
}

/**
 * Abre el reporte HTML del servidor en una pestaña nueva.
 *
 * Un enlace directo no puede llevar la cabecera X-API-Key, y ponerla en la URL
 * dejaría la clave en el historial y en los logs (AUDITORIA-1.0.md, COR-07). Se
 * pide con `fetch` (con la cabecera), se arma un Blob y se abre su URL temporal.
 * La pestaña se abre antes de pedir el reporte, dentro del gesto del usuario,
 * para que el bloqueador de ventanas emergentes no la frene.
 */
export async function openAuditReportHtml(jobId: string): Promise<void> {
  const tab = window.open("", "_blank");
  try {
    const res = await fetch(`${API_BASE}/api/v1/audits/${encodeURIComponent(jobId)}/report.html`, {
      headers: headers(),
    });
    if (!res.ok) {
      throw new ApiError(res.status, await parseErrorDetail(res));
    }
    const blob = new Blob([await res.text()], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    if (tab) {
      tab.location.href = url;
    } else {
      window.location.href = url;
    }
    // La pestaña ya cargó el contenido para entonces: liberar la URL evita
    // dejar el reporte retenido en memoria.
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  } catch (err) {
    tab?.close();
    throw err;
  }
}

export interface LaunchDriftOptions {
  dataset_id: string;
  reference_id: string;
  label_col?: string;
}

export async function launchDrift(opts: LaunchDriftOptions): Promise<JobCreatedResponse> {
  return request<JobCreatedResponse>("/api/v1/drift", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts),
  });
}

export async function getDriftStatus(jobId: string): Promise<JobStatusResponse> {
  return request<JobStatusResponse>(`/api/v1/drift/${encodeURIComponent(jobId)}`);
}

export async function listChecks(): Promise<CheckInfo[]> {
  return request<CheckInfo[]>("/api/v1/checks");
}
