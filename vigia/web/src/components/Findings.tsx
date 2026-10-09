import type { Finding, Severity } from "../types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Info",
};

const SEVERITY_VAR: Record<Severity, string> = {
  critical: "--sev-critical",
  high: "--sev-high",
  medium: "--sev-medium",
  low: "--sev-low",
  info: "--sev-info",
};

function formatMetricValue(v: number): string {
  if (Number.isInteger(v)) return v.toLocaleString("es-AR");
  return v.toPrecision(4).replace(/\.?0+$/, "");
}

function FindingCard({ finding }: { finding: Finding }) {
  const color = `var(${SEVERITY_VAR[finding.severity]})`;
  const metricEntries = Object.entries(finding.metric);

  return (
    <li className="finding" style={{ borderLeftColor: color }}>
      <details>
        <summary className="finding__summary">
          <span className="badge" style={{ background: color }}>
            {SEVERITY_LABEL[finding.severity]}
          </span>
          <span className="finding__title">{finding.title}</span>
        </summary>
        <div className="finding__body">
          <p className="cid">
            {finding.check_id} · {finding.affected_rows.toLocaleString("es-AR")} filas afectadas
          </p>
          <p>{finding.description}</p>
          {metricEntries.length > 0 && (
            <p className="cid finding__metrics">
              {metricEntries
                .map(([k, v]) => `${k}=${formatMetricValue(v)}`)
                .join(" · ")}
            </p>
          )}
          {finding.examples.length > 0 && <ExamplesTable examples={finding.examples} />}
          <div className="finding__rec">
            <strong>Recomendación:</strong> {finding.recommendation}
            {finding.auto_fix && (
              <span className="cid">
                {" "}
                (corrección automática sugerida: <code>{finding.auto_fix}</code>)
              </span>
            )}
          </div>
        </div>
      </details>
    </li>
  );
}

function ExamplesTable({ examples }: { examples: Record<string, unknown>[] }) {
  const cols = Object.keys(examples[0] ?? {});
  return (
    <div className="scroll finding__examples">
      <p className="cid">
        Ejemplo{examples.length !== 1 ? "s" : ""} ({examples.length})
      </p>
      <table>
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c} scope="col">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {examples.map((row, i) => (
            <tr key={i}>
              {cols.map((c) => (
                <td key={c}>{String(row[c] ?? "")}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface FindingsProps {
  findings: Finding[];
}

export function Findings({ findings }: FindingsProps) {
  if (findings.length === 0) {
    return (
      <div className="empty" role="status">
        Ningún check reportó hallazgos.
      </div>
    );
  }

  const grouped = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    items: findings
      .filter((f) => f.severity === sev)
      .sort((a, b) => a.check_id.localeCompare(b.check_id)),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="findings">
      {grouped.map((group) => (
        <section key={group.severity} aria-labelledby={`sev-${group.severity}`}>
          <h3 id={`sev-${group.severity}`} className="findings__group-heading">
            <span className="badge" style={{ background: `var(${SEVERITY_VAR[group.severity]})` }}>
              {SEVERITY_LABEL[group.severity]}
            </span>{" "}
            ({group.items.length})
          </h3>
          <ul className="findings__list">
            {group.items.map((f, i) => (
              <FindingCard key={`${i}-${f.check_id}`} finding={f} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
