# Auditoría de la 1.0

Cómo se revisó Vigía antes de publicar la versión 1.0.0, del 4 al 6 de octubre
de 2026. Todo se hizo con Claude (Anthropic) y **sin revisión humana**: no es una
auditoría independiente.

| Archivo | Qué es |
|---|---|
| [`AUDITORIA-1.0.md`](AUDITORIA-1.0.md) | La auditoría: 50 hallazgos (1 crítico, 8 altos), cómo se reprodujo cada uno y, en las secciones 8 y 9, cómo se corrigió, con el test de cada corrección |
| [`VERIFICACION-1.0.md`](VERIFICACION-1.0.md) | La verificación de esas correcciones. La hizo la misma sesión que las escribió y lo dice en su primer párrafo. Encontró 9 problemas más (VER-01 a VER-09); otra sesión de Claude reprodujo los 4 bloqueantes antes de corregirlos |
| [`prompts/`](prompts/) | Los prompts de cada etapa, en orden: `auditoria`, `remediacion`, `despliegue`, `verificacion` y `cierre` |

El historial de commits de este proyecto no se publica: este repositorio parte de
un solo commit. Los hashes que se citan en este archivo son del historial
original y no se pueden consultar aquí; los tests de cada corrección sí están
en `vigia/tests/`.

Los comentarios del código citan estos archivos por nombre y por id de hallazgo
(por ejemplo, `AUDITORIA-1.0.md, SEC-01`): buscando el id en el archivo se llega
al hallazgo, a su reproducción y a su corrección.
