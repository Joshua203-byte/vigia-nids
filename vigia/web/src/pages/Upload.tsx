import { useId, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, launchAudit, uploadDataset } from "../api";

const ACCEPTED_EXTENSIONS = [".csv", ".parquet", ".pq"];

function hasAcceptedExtension(name: string): boolean {
  const lower = name.toLowerCase();
  return ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export function UploadPage() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const labelColId = useId();
  const splitColId = useId();

  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [labelCol, setLabelCol] = useState("");
  const [splitCol, setSplitCol] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function pickFile(f: File | null) {
    setError(null);
    if (f && !hasAcceptedExtension(f.name)) {
      setError(
        `"${f.name}" no tiene una extensión soportada. La API acepta ${ACCEPTED_EXTENSIONS.join(", ")}.`,
      );
      setFile(null);
      return;
    }
    setFile(f);
  }

  async function handleSubmit() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      setStage("Subiendo dataset...");
      const uploaded = await uploadDataset(file);

      setStage("Lanzando auditoría...");
      const job = await launchAudit({
        dataset_id: uploaded.dataset_id,
        label_col: labelCol.trim() || undefined,
        split_col: splitCol.trim() || undefined,
      });

      navigate(`/resultado/${job.job_id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.message} (HTTP ${err.status})`);
      } else {
        setError(err instanceof Error ? err.message : "Error desconocido");
      }
      setBusy(false);
      setStage(null);
    }
  }

  return (
    <div>
      <h1>Auditar un dataset</h1>
      <p className="sub">
        Subí un CSV o Parquet. Vigía revisa duplicados, fuga de datos, atajos del
        modelo, ruido de etiqueta y más, y te dice qué tan confiable es antes de
        entrenar con él.
      </p>

      <div
        className={`dropzone ${dragOver ? "dragover" : ""}`}
        role="button"
        tabIndex={0}
        aria-label="Elegir o arrastrar un archivo CSV o Parquet"
        onClick={() => fileInputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            fileInputRef.current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const dropped = e.dataTransfer.files?.[0];
          if (dropped) pickFile(dropped);
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept={ACCEPTED_EXTENSIONS.join(",")}
          onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
        />
        {file ? (
          <p>
            <strong>{file.name}</strong> ({(file.size / (1024 * 1024)).toFixed(2)} MB)
          </p>
        ) : (
          <p>Arrastrá un archivo acá, o hacé clic para elegirlo (CSV o Parquet).</p>
        )}
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <h2 style={{ marginTop: 0 }}>Columnas (opcional)</h2>
        <p className="sub">
          Si no se indican, Vigía intenta detectarlas por nombre. Los checks que
          dependen de una columna que no se encuentra se saltan — y eso enciende el
          semáforo gris, no verde.
        </p>
        <div className="field">
          <label htmlFor={labelColId}>Columna de etiqueta (label_col)</label>
          <input
            id={labelColId}
            type="text"
            placeholder='ej. "Label"'
            value={labelCol}
            onChange={(e) => setLabelCol(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor={splitColId}>Columna de partición (split_col)</label>
          <input
            id={splitColId}
            type="text"
            placeholder='ej. "split"'
            value={splitCol}
            onChange={(e) => setSplitCol(e.target.value)}
          />
        </div>
      </div>

      {error && (
        <div className="error-box" role="alert">
          <strong>Error:</strong> {error}
        </div>
      )}

      <div style={{ marginTop: 20 }}>
        <button className="btn" disabled={!file || busy} onClick={handleSubmit}>
          {busy && <span className="spinner" aria-hidden="true" />}
          {busy ? (stage ?? "Procesando...") : "Auditar"}
        </button>
      </div>
    </div>
  );
}
