// Checks que fallaron por un error interno. Va aparte de SkippedChecks a
// propósito: saltarse es "no aplicaba a este dataset"; fallar es un defecto de
// Vigía, y mezclados un crash se leía como una columna que faltaba
// (AUDITORIA-1.0.md, COR-05). Como el gris, no se esconde detrás de un toggle.

interface ErrorChecksProps {
  errors: Record<string, string>;
}

export function ErrorChecks({ errors }: ErrorChecksProps) {
  const entries = Object.entries(errors).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return null;

  return (
    <section aria-labelledby="errors-heading" className="card error-checks" role="alert">
      <h2 id="errors-heading" className="error-checks__heading">
        Checks que fallaron ({entries.length})
      </h2>
      <p className="sub">
        Estos checks fallaron por un error interno de Vigía, no por el dataset. El
        reporte está incompleto: no se puede dar por limpio.
      </p>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Error</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([checkId, error]) => (
              <tr key={checkId}>
                <td>
                  <code>{checkId}</code>
                </td>
                <td>{error}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
