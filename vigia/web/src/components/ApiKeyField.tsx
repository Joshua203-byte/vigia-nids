import { useState } from "react";
import { setApiKey } from "../api";

// La API es opcionalmente autenticada por X-API-Key (docs/USO.md,
// "Autenticación"). En desarrollo normalmente VIGIA_API_KEY no está seteada
// y esto no hace falta, pero si alguien la configuró, necesita una forma de
// pasarla sin hardcodearla en el build. Un campo simple en la barra de
// navegación alcanza para las cuatro pantallas de este panel.
export function ApiKeyField() {
  const [value, setValue] = useState("");
  const [saved, setSaved] = useState(false);

  return (
    <form
      className="api-key-field"
      onSubmit={(e) => {
        e.preventDefault();
        setApiKey(value);
        setSaved(true);
        window.setTimeout(() => setSaved(false), 1500);
      }}
    >
      <label htmlFor="api-key-input">Clave de API (opcional)</label>
      <input
        id="api-key-input"
        type="password"
        autoComplete="off"
        placeholder="X-API-Key"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button type="submit" className="btn btn-secondary btn-small">
        {saved ? "Guardada" : "Usar"}
      </button>
    </form>
  );
}
