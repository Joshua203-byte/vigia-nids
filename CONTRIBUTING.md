# Contributing to Vigía

Thanks for taking the time. Issues and pull requests can be written in English
or Spanish.

## The most useful contributions

1. **False positives and false negatives on real datasets.** Vigía exists to
   tell you whether a dataset is clean; a finding that is wrong, or a defect it
   misses, is the most valuable report you can send. Use the "Wrong finding"
   issue template and include the dataset name and version, the command, and
   the relevant part of `report.json`. Please do not attach datasets: a link to
   the public source is enough.
2. **Bugs** in the CLI, the readers, the API or the dashboard.
3. **New checks or dataset profiles**, ideally discussed in an issue first.

To report a security vulnerability, do not open an issue: see
[`SECURITY.md`](SECURITY.md).

## Development setup

```bash
git clone https://github.com/Joshua203-byte/vigia-nids.git
cd vigia-nids/vigia
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -e ".[dev,ml,parquet,api]"
```

Before opening a pull request, the same checks the CI runs must pass:

```bash
pytest -q --cov=src               # coverage must stay at or above 85 %
ruff check src tests
ruff format --check src tests
mypy src
```

If you touch the dashboard (`vigia/web/`): `npm ci`, `npm run lint` and
`npm run build`. CI runs on Linux and Windows with Python 3.11, 3.12 and 3.13.

## Conventions

The project has a few conventions that are not the usual ones. The CI enforces
some of them; please follow the others too.

- **Code, docstrings, messages and docs are in Spanish** (Río de la Plata,
  with *vos*). This English file and the root README are the exceptions. If
  you do not write Spanish, open the pull request anyway: the maintainer will
  translate the user-facing text.
- **Comments explain why, not what.** The existing code is the model: a
  docstring says which failure the code prevents and, when it fixes a reported
  problem, cites it (for example `AUDITORIA-1.0.md, SEC-01`).
- **Source text must fit in cp1252**, so that the Windows console can print
  it. `tests/unit/test_encoding.py` fails otherwise (no `→`, `≥` or emoji in
  `src/`).
- **Line length is 100** (ruff).
- **A bug fix comes with a test that fails without the fix.** Run the new test
  against the old code and check that it fails for the right reason. A test
  that passes before and after the fix does not prove anything.
- **A check that cannot run must say why.** Raise `CheckSkipped` with a reason
  the user can act on; never return an empty list for "I could not look". An
  unexpected exception is reported as an error and turns the traffic light red.
- **No datasets in the repository.** Tests use small synthetic data
  generated in the test itself.

Adding a check or a fix is documented step by step in
[`vigia/docs/ARQUITECTURA.md`](vigia/docs/ARQUITECTURA.md) ("Agregar un check",
"Agregar una corrección").

## Commits

One commit per change, as small as possible without leaving the tree broken:
every commit has to pass the test suite. The message explains why the change
was needed, not only what changed:

```
fix(leak.temporal): no descartar en silencio tiempos sin interpretar

What was happening, why, what the tests did not catch, and how it was
verified.
```

The history of this repository follows that format (`git log`) and is the
best reference.

## Pull requests

- Keep each pull request to one topic.
- Say in the description what you ran to verify it.
- If the change modifies the JSON report, the exit codes or a check id, say so:
  those are public contracts ([`vigia/docs/ARQUITECTURA.md`](vigia/docs/ARQUITECTURA.md),
  "Qué es API pública y qué no") and they go into `vigia/CHANGELOG.md`.

By contributing you agree that your contribution is licensed under the
[Apache 2.0 license](LICENSE).
