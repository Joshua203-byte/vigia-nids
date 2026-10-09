# Vigía — imagen única que sirve la API REST y el panel web
# (docs/PLAN.md, fase 3.5).
#
# Un solo contenedor: FastAPI sirve la API bajo /api/v1 y /health, y el
# build estático del panel (web/dist) montado en / vía StaticFiles
# (ver src/vigia/api/app.py, `VIGIA_WEB_DIST`). Esto evita un segundo
# contenedor con nginx solo para servir archivos estáticos -- para cuatro
# pantallas no vale la pena el proxy aparte.
#
# `docker compose up` deja todo navegable en http://localhost:8000.

# ---- Etapa 1: build del frontend --------------------------------------
# Las imagenes base van fijadas por digest (el del indice multi-plataforma,
# verificado con `docker buildx imagetools inspect`): `22-slim` y `3.12-slim`
# son etiquetas que se mueven, y una imagen de produccion no puede cambiar
# debajo de un build repetido (AUDITORIA-1.0.md, SEC-09). Para actualizarlas,
# se vuelve a inspeccionar la etiqueta y se cambia el digest en un commit.
FROM node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS web-build
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# VITE_API_BASE_URL vacío: el panel y la API comparten origen en este
# contenedor (mismo proceso, mismo puerto), así que las rutas relativas
# alcanzan y no hace falta hardcodear un host.
ENV VITE_API_BASE_URL=""
RUN npm run build

# ---- Etapa 2: runtime Python -------------------------------------------
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d AS runtime

# No se instala nada con apt: ni herramientas de compilacion (pyarrow y demas
# traen wheels precompilados para slim) ni curl, que solo servia para el
# healthcheck y ahora lo hace Python.

# Usuario sin privilegios (docs/PLAN.md, 3.5): nunca corremos como root.
RUN groupadd --system vigia && useradd --system --gid vigia --home-dir /app --shell /usr/sbin/nologin vigia

WORKDIR /app

# Instalar el paquete con el extra `api`. `parquet` va también: es el
# formato recomendado para encadenar auditorías (docs/USO.md) y sin
# pyarrow la API no podría leer .parquet subidos.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[api,parquet]"

# Panel estático ya compilado, en la ruta que `VIGIA_WEB_DIST` espera por
# defecto (web/dist relativo al directorio de trabajo del proceso). Queda
# propiedad de root y sin permiso de escritura para `vigia`: si alguien logra
# ejecutar codigo en el proceso, no puede reemplazar el JavaScript que se le
# sirve a los demas usuarios (AUDITORIA-1.0.md, SEC-09).
COPY --from=web-build --chown=root:root /web/dist ./web/dist
RUN chmod -R a-w /app/web/dist

# Directorio para datasets/uploads temporales (docs/PLAN.md, 3.5): un
# volumen se monta acá desde docker-compose.yml. El propio storage.py usa
# `tempfile.mkdtemp`, así que esto es principalmente para dejar un punto de
# montaje estable y, si se quiere, apuntar TMPDIR ahí.
# Solo /data es escribible por `vigia`; /app (codigo y panel) no.
RUN mkdir -p /data/uploads && chown -R vigia:vigia /data

# FORWARDED_ALLOW_IPS: de que direcciones uvicorn acepta X-Forwarded-For (la IP
# real del cliente, que usa el limitador de peticiones, AUDITORIA-1.0.md,
# SEC-03). Por defecto solo el propio contenedor; el compose de produccion pone
# la red donde esta el proxy. Nunca "*": cualquiera podria inventarse su IP.
ENV TMPDIR=/data/uploads \
    PYTHONUNBUFFERED=1 \
    FORWARDED_ALLOW_IPS=127.0.0.1

USER vigia

EXPOSE 8000

# Sin curl: urlopen levanta una excepcion (y el proceso sale con 1) si /health
# no responde 200.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]

CMD ["uvicorn", "vigia.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
