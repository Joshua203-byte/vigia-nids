import type { TrafficLightColor } from "../types";
import "./TrafficLight.css";

// El semáforo es la pieza de accesibilidad más importante del panel
// (docs/PLAN.md, fase 3.4 y 3.1): nunca solo color. Cada estado lleva un
// ícono (forma, no solo color) y la palabra completa, visible siempre, no en
// un `title` ni en texto para lectores de pantalla únicamente.
//
// El gris es la parte más fácil de arruinar: "no encontré nada" (verde) y
// "no pude revisar todo" (gris) no son lo mismo, y este componente los
// distingue con la misma jerarquía visual — el gris no es un texto chico al
// costado, es tan grande como el rojo.

const LABELS: Record<TrafficLightColor, string> = {
  rojo: "Rojo — hallazgos graves o un check falló",
  amarillo: "Amarillo — hallazgos menores",
  verde: "Verde — sin hallazgos, todos los checks corrieron",
  gris: "Gris — no se pudo revisar todo",
};

const SHORT_LABELS: Record<TrafficLightColor, string> = {
  rojo: "Rojo",
  amarillo: "Amarillo",
  verde: "Verde",
  gris: "Gris",
};

const DESCRIPTIONS: Record<TrafficLightColor, string> = {
  rojo:
    "Se encontraron hallazgos críticos o de alta severidad, o un check falló por un " +
    "error interno (ver abajo). Revisar antes de entrenar.",
  amarillo: "Se encontraron hallazgos de severidad media o baja.",
  verde: "Ningún check reportó problemas y todos los checks planificados corrieron.",
  gris:
    "Uno o más checks no se ejecutaron. Esto NO significa que el dataset esté limpio: " +
    "significa que no se pudo revisar todo. Ver la lista de checks no ejecutados abajo.",
};

// Íconos como SVG inline, con una forma distinta por estado (no solo el
// color relleno), para que sean distinguibles incluso en escala de grises.
function Icon({ color }: { color: TrafficLightColor }) {
  switch (color) {
    case "rojo":
      // Octágono con X: forma de "detener".
      return (
        <svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false">
          <path
            fill="currentColor"
            d="M8 2h8l6 6v8l-6 6H8l-6-6V8l6-6Z"
          />
          <path
            stroke="#fff"
            strokeWidth="2"
            strokeLinecap="round"
            d="M9 9l6 6M15 9l-6 6"
          />
        </svg>
      );
    case "amarillo":
      // Triángulo de advertencia con signo de exclamación.
      return (
        <svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false">
          <path fill="currentColor" d="M12 2 1 21h22L12 2Z" />
          <rect x="11" y="9" width="2" height="6" fill="#fff" />
          <rect x="11" y="16" width="2" height="2" fill="#fff" />
        </svg>
      );
    case "verde":
      // Círculo con tilde.
      return (
        <svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false">
          <circle cx="12" cy="12" r="10" fill="currentColor" />
          <path
            stroke="#fff"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="none"
            d="M7 12.5l3.2 3.2L17 9"
          />
        </svg>
      );
    case "gris":
      // Círculo con signo de pregunta: "no se sabe", distinto de "está bien".
      return (
        <svg viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false">
          <circle cx="12" cy="12" r="10" fill="currentColor" />
          <text
            x="12"
            y="16.5"
            textAnchor="middle"
            fontSize="13"
            fontWeight="700"
            fill="#fff"
            fontFamily="system-ui, sans-serif"
          >
            ?
          </text>
        </svg>
      );
  }
}

interface TrafficLightProps {
  color: TrafficLightColor;
  /** Si es true, se muestra en tamaño reducido (para usar en listas). */
  compact?: boolean;
}

export function TrafficLight({ color, compact = false }: TrafficLightProps) {
  return (
    <div
      className={`traffic-light traffic-light--${color} ${compact ? "traffic-light--compact" : ""}`}
      role="status"
      aria-label={LABELS[color]}
    >
      <span className="traffic-light__icon" style={{ color: `var(--light-${color})` }}>
        <Icon color={color} />
      </span>
      <span className="traffic-light__text">
        <span className="traffic-light__word">{SHORT_LABELS[color]}</span>
        {!compact && <span className="traffic-light__desc">{DESCRIPTIONS[color]}</span>}
      </span>
    </div>
  );
}
