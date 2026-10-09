# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No (0.2.0 had a critical API flaw fixed in 1.0.0: upgrade) |

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:
go to the [Security tab](https://github.com/Joshua203-byte/vigia-nids/security) and
click **Report a vulnerability**. Only the maintainer sees the report.

Include what you can of:

- the version (`vigia version`) and how Vigía was run (CLI, Python library,
  `vigia serve`, the Docker image or `deploy/docker-compose.prod.yml`);
- the steps or a minimal file that reproduces it;
- what an attacker gains (read, delete, run code, deny service).

Vigía is maintained by one person. You can expect an acknowledgement within a
week and, for confirmed issues, a fix or a mitigation plan as soon as
possible. You will be credited in the release notes unless you prefer not to
be.

## Scope

In scope:

- **The REST API and the dashboard** (`vigia serve`, the Docker image, the
  production compose file): authentication bypass, access to or deletion of
  another upload, path traversal, denial of service that gets past the
  documented limits.
- **Dataset parsing.** Vigía reads files that come from third parties (CSV,
  Parquet, Zeek, Suricata EVE, PCAP). A crafted file that executes code,
  reads files outside its input, or exhausts memory beyond the configured
  limits is in scope.
- **The report.** Values from the dataset end up in the HTML report; an
  injection that runs script in it is in scope.

Known limitations, documented in
[`vigia/docs/DESPLIEGUE.md`](vigia/docs/DESPLIEGUE.md) and not considered
vulnerabilities on their own:

- Clients that share the API key are not isolated from each other: anyone with
  the key and a job id can read that job's report.
- There is no per-job time limit.
- Without `VIGIA_API_KEY` the API is open by design for local development (it
  logs a warning); with `VIGIA_ENV=production` it refuses to start without it.

## Previous audit

The 1.0.0 code went through an audit, fixes and a verification, all done with
Claude and with no human reviewer. Findings and fixes are in
[`auditoria-1.0/`](auditoria-1.0/). Treat it as a starting point, not as a
guarantee.
