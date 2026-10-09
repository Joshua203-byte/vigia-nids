// Lista de checks no ejecutados. docs/PLAN.md, fase 3.1 es explícito: esto
// tiene que estar siempre visible cuando no está vacío, no detrás de un
// `<details>` que nadie abre. Por eso este componente no colapsa nada: si
// hay algo que mostrar, ocupa su lugar en la pantalla igual que los
// hallazgos.

interface SkippedChecksProps {
  skipped: Record<string, string>;
}

export function SkippedChecks({ skipped }: SkippedChecksProps) {
  const entries = Object.entries(skipped).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return null;

  return (
    <section aria-labelledby="skipped-heading" className="card skipped-checks">
      <h2 id="skipped-heading" className="skipped-checks__heading">
        Checks que no se ejecutaron ({entries.length})
      </h2>
      <p className="sub">
        Estos checks no corrieron, así que no dicen nada sobre esa parte del dataset —
        ni bien ni mal. Un dataset con cero hallazgos pero checks saltados no está
        confirmado como limpio.
      </p>
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Motivo</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([checkId, reason]) => (
              <tr key={checkId}>
                <td>
                  <code>{checkId}</code>
                </td>
                <td>{reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
