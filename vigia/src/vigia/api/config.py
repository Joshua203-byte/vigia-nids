"""Configuracion de la API: todas las variables de entorno en un solo lugar.

Antes cada limite se leia de ``os.environ`` donde se usaba, con un ``int(...)``
pelado: un valor mal escrito (``VIGIA_MAX_UPLOAD_MB=mucho``) explotaba con un
``ValueError`` en la primera peticion, no al arrancar, y nadie sabia cual de
las variables era la culpable (AUDITORIA-1.0.md, SEC-05). Ahora se leen y se
validan juntas: ``load_settings()`` levanta ``ConfigError`` con el nombre de la
variable, y el ``lifespan`` de la app la llama al arrancar.

Se sigue leyendo el entorno en cada llamada (es barato) para que los tests
puedan cambiar una variable sin reiniciar el proceso.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

#: Limite de subida por defecto. PLAN.md pedia bajarlo de 500 MB: una auditoria
#: de 1 M x 80 llega a 5,4 GiB de pico en un servidor de 8 GB, y un archivo
#: grande cuesta el doble en disco (el archivo mas su lectura). Quien necesite
#: mas lo sube con ``VIGIA_MAX_UPLOAD_MB``.
DEFAULT_MAX_UPLOAD_MB = 200
DEFAULT_RATE_LIMIT_PER_MINUTE = 30
#: Minutos que una subida puede esperar sin que ningun trabajo la use antes de
#: borrarse (AUDITORIA-1.0.md, SEC-02).
DEFAULT_UPLOAD_TTL_MINUTES = 30
#: Tope del directorio de subidas. El servidor de despliegue tiene 80 GB de
#: disco; 2 GiB alcanzan para algunas subidas simultaneas sin arriesgarlo.
DEFAULT_STORAGE_QUOTA_MB = 2048
#: Una auditoria de 1 M x 80 pica a 5,4 GiB; en 8 GB de RAM mas de una a la vez
#: es riesgo de OOM. Lo que sobra espera en una cola chica y, llena, se rechaza.
DEFAULT_MAX_CONCURRENT_JOBS = 1
DEFAULT_MAX_QUEUED_JOBS = 4
#: Los trabajos terminados (con su reporte) caducan y hay un tope en memoria.
DEFAULT_REPORT_TTL_MINUTES = 60
DEFAULT_MAX_STORED_JOBS = 200
#: Tope de filas y de memoria estimada (filas x columnas x 8 bytes) de un dataset
#: subido. Un Parquet de 114 KiB puede descomprimir a 50 M de filas: se mira el pie
#: del archivo, no el contenido (AUDITORIA-1.0.md, SEC-04).
#:
#: 700 MB porque el pico de una auditoria es ~8,4 veces esa estimacion: 1 M x 80
#: son 640 MB y picaron a 5,4 GiB. El defecto anterior, 4096, dejaba pasar datasets
#: de ~34 GiB de pico en un contenedor de 6 (VERIFICACION-1.0.md, VER-09). Quien
#: tenga mas memoria lo sube con `VIGIA_MAX_EXPANDED_MB`; al arrancar se avisa si
#: el valor por el factor no entra en la memoria disponible.
DEFAULT_MAX_ROWS = 5_000_000
DEFAULT_MAX_EXPANDED_MB = 700
PEAK_MEMORY_FACTOR = 8


#: Origenes que se permiten sin configurar nada: el dev server de Vite y la
#: propia API (cuando sirve el panel como estatico).
DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000"
ENVIRONMENTS = ("development", "production")


class ConfigError(ValueError):
    """Una variable de entorno de la API tiene un valor que no sirve."""


def _int_env(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} no es un entero") from None
    if value < minimum:
        raise ConfigError(f"{name}={value} es menor que el minimo permitido ({minimum})")
    return value


@dataclass(frozen=True)
class Settings:
    max_upload_mb: int
    rate_limit_per_minute: int
    upload_ttl_minutes: int
    storage_quota_mb: int
    max_concurrent_jobs: int
    max_queued_jobs: int
    report_ttl_minutes: int
    max_stored_jobs: int
    max_rows: int
    max_expanded_mb: int
    env: str
    cors_origins: tuple[str, ...]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_expanded_bytes(self) -> int:
        return self.max_expanded_mb * 1024 * 1024

    @property
    def storage_quota_bytes(self) -> int:
        return self.storage_quota_mb * 1024 * 1024


def _env_name() -> str:
    env = os.environ.get("VIGIA_ENV", "development").strip().lower()
    if env not in ENVIRONMENTS:
        raise ConfigError(f"VIGIA_ENV={env!r} no es valido; usa uno de {', '.join(ENVIRONMENTS)}")
    # En produccion la API no puede arrancar abierta: sin clave cualquiera que
    # llegue al puerto sube datasets y lanza trabajos (AUDITORIA-1.0.md, SEC-09).
    # Un typo en VIGIA_ENV se rechaza arriba, asi no se salta este control.
    if env == "production" and not os.environ.get("VIGIA_API_KEY"):
        raise ConfigError("VIGIA_ENV=production exige VIGIA_API_KEY (no puede estar vacia)")
    return env


def _cors_origins() -> tuple[str, ...]:
    raw = os.environ.get("VIGIA_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    origins = tuple(o.strip() for o in raw.split(",") if o.strip())
    # "*" dejaria que cualquier sitio le hable a la API desde el navegador de
    # un usuario (AUDITORIA-1.0.md, SEC-12): hay que nombrar los origenes.
    if "*" in origins:
        raise ConfigError("VIGIA_CORS_ORIGINS no puede contener '*': lista los origenes")
    return origins


def container_memory_bytes() -> int | None:
    """Memoria que puede usar este proceso, o ``None`` si no se puede saber.

    Lee el limite del cgroup (v2 y v1), que es el que importa dentro de Docker;
    sin limite ("max" o un valor absurdo) usa la memoria fisica donde hay
    ``sysconf``.
    """
    for ruta in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(ruta, encoding="ascii") as f:
                crudo = f.read().strip()
        except OSError:
            continue
        if crudo.isdigit() and int(crudo) < 1 << 60:
            return int(crudo)
    if sys.platform == "win32":
        return None
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError):
        return None


def memory_warning(settings: Settings) -> str | None:
    """Mensaje si ``max_expanded_mb`` por el factor del pico no entra en memoria."""
    memoria = container_memory_bytes()
    if memoria is None:
        return None
    pico = settings.max_expanded_bytes * PEAK_MEMORY_FACTOR
    if pico <= memoria:
        return None
    return (
        f"VIGIA_MAX_EXPANDED_MB={settings.max_expanded_mb} admite datasets cuyo pico de "
        f"memoria (~{PEAK_MEMORY_FACTOR}x, {pico / 1024**3:.1f} GiB) supera los "
        f"{memoria / 1024**3:.1f} GiB disponibles: una auditoria grande podria matar el "
        "proceso. Baja el valor o dale mas memoria al contenedor."
    )


def rate_limit_per_minute() -> int:
    """Solo el limite de peticiones: el limitador lo pide en cada peticion y no
    hace falta releer ni validar las otras once variables para eso."""
    return _int_env("VIGIA_RATE_LIMIT_PER_MINUTE", DEFAULT_RATE_LIMIT_PER_MINUTE, 1)


def load_settings() -> Settings:
    """Lee y valida el entorno. Cero MB es valido (todo contenido lo supera, y
    lo usan los tests); un limite de peticiones de cero bloquearia todo."""
    return Settings(
        max_upload_mb=_int_env("VIGIA_MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB, 0),
        rate_limit_per_minute=rate_limit_per_minute(),
        upload_ttl_minutes=_int_env("VIGIA_UPLOAD_TTL_MINUTES", DEFAULT_UPLOAD_TTL_MINUTES, 1),
        storage_quota_mb=_int_env("VIGIA_STORAGE_QUOTA_MB", DEFAULT_STORAGE_QUOTA_MB, 1),
        max_concurrent_jobs=_int_env("VIGIA_MAX_CONCURRENT_JOBS", DEFAULT_MAX_CONCURRENT_JOBS, 1),
        max_queued_jobs=_int_env("VIGIA_MAX_QUEUED_JOBS", DEFAULT_MAX_QUEUED_JOBS, 0),
        report_ttl_minutes=_int_env("VIGIA_REPORT_TTL_MINUTES", DEFAULT_REPORT_TTL_MINUTES, 1),
        max_stored_jobs=_int_env("VIGIA_MAX_STORED_JOBS", DEFAULT_MAX_STORED_JOBS, 1),
        max_rows=_int_env("VIGIA_MAX_ROWS", DEFAULT_MAX_ROWS, 1),
        max_expanded_mb=_int_env("VIGIA_MAX_EXPANDED_MB", DEFAULT_MAX_EXPANDED_MB, 1),
        env=_env_name(),
        cors_origins=_cors_origins(),
    )
