# Despliegue

Cómo poner la API y el panel de Vigía en un servidor propio, con HTTPS y la
clave de API obligatoria. Pensado para **un servidor chico y una sola
instancia**: 4 vCPU, 8 GB de RAM y 80 GB de disco (un Hetzner CX33, por
ejemplo), pocos clientes que comparten una clave.

> **Estado:** estos archivos se probaron en local (el compose de producción con
> Caddy y `tls internal`, ver [Probarlo en local](#probarlo-en-local)). Todavía
> no se corrieron en un servidor real: el primer despliegue es también la
> primera prueba de HTTPS con un dominio público, de los límites de memoria con
> datos reales y de Caddy pidiendo un certificado. Miralo de cerca.

Los archivos están en [`deploy/`](../deploy/): `docker-compose.prod.yml`,
`Caddyfile` y `.env.example`. Para probar en tu máquina sin servidor, mirá
[Probarlo en local](#probarlo-en-local).

## Requisitos

- Docker con Compose v2.
- Un dominio con un registro A hacia la IP del servidor.
- Los puertos **80 y 443** abiertos (Caddy pide el certificado a Let's Encrypt
  por el 80).
- La imagen `ghcr.io/joshua203-byte/vigia-nids:<versión>`. Todavía no está
  publicada: hasta entonces se construye en el servidor con
  `docker build -t ghcr.io/joshua203-byte/vigia-nids:1.0.0 .` desde `vigia/`.

## Variables

Se ponen en `deploy/.env` (copiá `deploy/.env.example`; el archivo no se versiona
ni entra a la imagen).

| Variable | Qué hace | Por defecto en el código | En el compose de producción |
|---|---|---|---|
| `VIGIA_DOMAIN` | Dominio público (obligatoria) | — | sin valor: hay que ponerlo |
| `VIGIA_VERSION` | Etiqueta de la imagen (obligatoria) | — | sin valor: hay que ponerlo |
| `VIGIA_API_KEY` | Clave que mandan los clientes en `X-API-Key` (obligatoria) | — | sin valor: hay que ponerla |
| `VIGIA_MAX_UPLOAD_MB` | Tamaño máximo de una subida; Caddy y la API usan el mismo | 200 | 200 |
| `VIGIA_RATE_LIMIT_PER_MINUTE` | Peticiones por minuto y por IP | 30 | 30 |
| `VIGIA_MAX_CONCURRENT_JOBS` | Trabajos que corren a la vez | 1 | 1 |
| `VIGIA_STORAGE_QUOTA_MB` | Tope del disco de subidas | 2048 | **4096** (hay 80 GB de disco) |
| `VIGIA_MAX_EXPANDED_MB` | Memoria estimada máxima de un dataset (filas × columnas × 8 bytes) | 700 | 700 (no está en el compose: usa el del código) |

La API tiene más variables (cola, caducidades, topes de filas); están en
[`USO.md`](USO.md#límites-y-seguridad). Con `VIGIA_ENV=production`, que el
compose ya setea, **la API no arranca sin `VIGIA_API_KEY`** ni con `*` en
`VIGIA_CORS_ORIGINS`: la imagen de producción nunca queda abierta en silencio.

### Generar la clave

```
openssl rand -hex 32
```

Se la das a los clientes por un canal que no sea el repositorio. Para rotarla,
cambiá el valor en `.env` y reiniciá (`docker compose ... up -d`).

## Levantar

```
cd deploy
cp .env.example .env        # completar dominio, versión y clave
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps     # la API tiene que figurar "healthy"
```

La API **no publica ningún puerto en el host**: solo Caddy le llega, por la red
interna. Caddy pide el certificado la primera vez que alguien entra al dominio.

## Ver los logs

```
docker compose -f docker-compose.prod.yml logs -f vigia
docker compose -f docker-compose.prod.yml logs -f caddy
```

Cuando una auditoría falla, el cliente recibe un mensaje genérico con un id
(`id: 3fa9c2b01d4e`). El detalle completo, con el traceback, está en el log de
`vigia` buscando ese id.

## Actualizar

```
docker compose -f docker-compose.prod.yml pull vigia   # o construir la imagen nueva
# cambiar VIGIA_VERSION en .env
docker compose -f docker-compose.prod.yml up -d
```

Los trabajos en curso y los reportes viven en memoria: **se pierden al
reiniciar**. Avisá a los clientes o esperá a que no haya nada corriendo.

## Qué vigilar

- **Disco.** Las subidas viven en el volumen `vigia_uploads`. Se borran al
  terminar el trabajo, a los 30 minutos si nadie las usó, y la API rechaza con
  `507` al pasar `VIGIA_STORAGE_QUOTA_MB`. Aun así, mirá `df -h` y
  `docker system df` de vez en cuando: las imágenes viejas se acumulan.
- **Memoria.** Una auditoría de 1 M de filas × 80 columnas llega a 5,4 GiB. El
  contenedor tiene un tope de 6 GB: pasado el tope, Docker lo mata a él (y lo
  reinicia) en vez de dejar sin memoria al servidor. Con `docker stats` se ve el
  uso real. El pico es ~8 veces la memoria cruda del dataset, y por eso
  `VIGIA_MAX_EXPANDED_MB` vale 700 (1 M de filas × 80 columnas ≈ 640 MB): la API
  rechaza con `413` lo que lo supere, y al arrancar avisa en el log si el valor × 8
  no entra en la memoria del contenedor. Subir ese tope con 8 GB en total no es
  una opción.
- **Reinicios del contenedor** (`docker compose ps`, columna de estado): uno
  repetido suele ser un trabajo que se pasó de memoria.
- **Certificado.** Caddy lo renueva solo; si falla, el motivo está en
  `logs caddy`. No borres el volumen `caddy_data`.

## Límites conocidos

- **Una sola instancia.** La cola de trabajos, el limitador de peticiones y los
  reportes están en memoria del proceso. **No se puede correr con más de un
  contenedor ni con `--workers` mayor a 1**: cada proceso tendría su propia cola
  y su propio contador.
- **Los reportes caducan** (60 minutos por defecto) y no sobreviven a un
  reinicio. Un `GET` de uno caducado da `410`.
- **Un dataset por trabajo.** El archivo se borra cuando el trabajo termina; para
  volver a auditarlo hay que subirlo otra vez.
- **Sin Caddy** (por ejemplo, `docker compose up` del compose de desarrollo) la
  API no tiene HTTPS ni el tope de cuerpo del proxy; sigue aplicando el suyo
  (`VIGIA_MAX_UPLOAD_MB`), pero no es una configuración para internet.

## Límites de seguridad: a quién darle la clave

Esta instalación está pensada para **pocos clientes de confianza** que comparten
una sola clave. Dos cosas que conviene saber antes de dársela a alguien:

- **No hay aislamiento entre clientes.** No hay usuarios ni permisos por cliente, y
  no se puede revocar a uno solo sin rotar la clave de todos. Quien tiene la clave
  y conoce el `job_id` de un trabajo (32 caracteres al azar) puede leer su reporte,
  que **incluye filas e IPs reales del dataset** que se auditó. Los `job_id` no se
  listan en ninguna parte, pero tampoco están atados a quien los lanzó.
- **No hay tope de tiempo por trabajo.** Un trabajo dura en proporción a las filas
  (unos 3 minutos por millón en las pruebas) y puede haber hasta 5 millones. Con un
  trabajo corriendo y cuatro en la cola, un cliente con la clave puede tener el
  servicio ocupado durante horas, sin querer o queriendo. Un trabajo colgado ocupa
  su lugar hasta que se reinicie el contenedor.

El criterio para los dos casos es el mismo: **dale la clave solo a gente de
confianza**. Un tope de tiempo de verdad exige correr cada trabajo en un proceso
aparte (a un hilo no se lo puede matar): queda como pendiente posterior a la 1.0.

## Probarlo en local

Sirve para ver que todo se levanta antes de tocar un servidor. Con
`VIGIA_DOMAIN=localhost` Caddy usa su CA interna (el navegador avisa del
certificado; `curl -k` lo acepta).

```
cd vigia
docker build -t ghcr.io/joshua203-byte/vigia-nids:local .
cd deploy
# .env con VIGIA_DOMAIN=localhost, VIGIA_VERSION=local, una VIGIA_API_KEY de prueba
# y, si el 80 y el 443 están ocupados, VIGIA_HTTP_PORT=8080 y VIGIA_HTTPS_PORT=8443
docker compose -f docker-compose.prod.yml up -d

curl -k https://localhost:8443/api/v1/checks                                  # 401
curl -k -H "X-API-Key: <la clave>" https://localhost:8443/api/v1/checks       # 200
curl -kI https://localhost:8443/                                              # cabeceras de seguridad
curl -k https://localhost:8443/resultado/abc                                  # el panel (200)
```

El panel guarda la clave solo en memoria: hay que pegarla en el campo de la
barra cada vez que se recarga la página.
