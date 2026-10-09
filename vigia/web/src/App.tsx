import { Suspense, lazy } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { ApiKeyField } from "./components/ApiKeyField";
import { FixPage } from "./pages/Fix";
import { ResultPage } from "./pages/Result";
import { UploadPage } from "./pages/Upload";

// Recharts (usado solo en Deriva) pesa bastante del bundle total; separarlo
// en un chunk aparte evita que las otras tres pantallas paguen ese costo.
const DriftPage = lazy(() => import("./pages/Drift").then((m) => ({ default: m.DriftPage })));

function NotFound() {
  return (
    <div>
      <h1>No encontrado</h1>
      <p>Esta página no existe. Volvé a Subir para empezar una auditoría nueva.</p>
    </div>
  );
}

export default function App() {
  return (
    <div className="app-shell">
      <nav className="app-nav" aria-label="Navegación principal">
        <span className="brand">Vigía</span>
        <NavLink to="/" end>
          Subir
        </NavLink>
        <NavLink to="/deriva">Deriva</NavLink>
        <ApiKeyField />
      </nav>

      <main>
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/resultado/:jobId" element={<ResultPage />} />
          <Route path="/corregir/:jobId" element={<FixPage />} />
          <Route
            path="/deriva"
            element={
              <Suspense fallback={<p>Cargando...</p>}>
                <DriftPage />
              </Suspense>
            }
          />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}
