## What and why

<!-- What problem this solves. Link the issue if there is one. -->

## How it was verified

<!-- What you ran. For a bug fix: the new test fails without the fix. -->

- [ ] `pytest -q --cov=src`, `ruff check src tests`, `ruff format --check src tests` and `mypy src` pass
- [ ] `npm run lint` and `npm run build` pass (only if `vigia/web/` changed)
- [ ] Changes the JSON report, an exit code or a check id: noted in `vigia/CHANGELOG.md`
