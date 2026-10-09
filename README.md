# Vigía

**Quality control for the datasets behind network intrusion detection models.**

[![PyPI](https://img.shields.io/pypi/v/vigia-nids)](https://pypi.org/project/vigia-nids/)
[![Python](https://img.shields.io/pypi/pyversions/vigia-nids)](https://pypi.org/project/vigia-nids/)
[![CI](https://github.com/Joshua203-byte/vigia-nids/actions/workflows/ci.yml/badge.svg)](https://github.com/Joshua203-byte/vigia-nids/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

A 0.99 F1 on an intrusion detector can be a property of the data, not of the
model. The most widely used public datasets (CIC-IDS2017, CSE-CIC-IDS2018,
UNSW-NB15, NSL-KDD) have documented duplicates, wrong labels, train/test
leakage and columns that give the answer away. Vigía finds those problems
before you train, tells you how much of your score they explain, and keeps
watching once the model is in production.

> **Language note.** The CLI, the reports and the technical documentation are
> in Spanish. This page is the English entry point; the full manual is
> [`vigia/README.md`](vigia/README.md).

## What it finds

Run on NSL-KDD, the train and test files are each deduplicated, yet 610 rows
are identical across them (2.7% of the test set). Deduplicating each file
separately does not catch it:

```console
$ pip install vigia-nids
$ vigia audit nsl_kdd.csv

Semáforo: ROJO  · 148,517 filas × 44 columnas
critical: 1  high: 3  medium: 1  low: 2

Sev       Check              Hallazgo                                          Filas
critical  dup.cross_split    1,220 filas aparecen en más de un split           1,220
high      dup.near           97,014 filas son casi duplicadas de otra          97,014
high      labels.conflict    18 grupos de filas idénticas tienen etiquetas...     37
high      labels.noise       2,113 etiquetas probablemente incorrectas (1.42%)  2,113
...
```

(`dup.cross_split` counts both copies: 1,220 rows are 610 pairs.)

On CIC-IDS2017, a split by capture day gives a recall of **0.00** for DoS Hulk,
PortScan and DDoS in all 10 seeds tried, while a random split gives anywhere
from 0 to almost 1 depending on the seed: the model had learned the capture
session, not the attacks. All figures, including the ones
where Vigía performs poorly, are in
[`vigia/benchmarks/RESULTADOS.md`](vigia/benchmarks/RESULTADOS.md).

## Three modules, 25 checks

| Module | Command | Question it answers |
|---|---|---|
| Dataset audit (16 checks) | `vigia audit` | Does this dataset have defects that inflate the metrics? Duplicates, cross-split duplicates, temporal / host / session leakage, shortcut columns, label noise, invalid values |
| Poisoning (4 detectors) | `vigia poison` | Did someone insert records to manipulate the model? |
| Drift (5 checks) | `vigia drift` | Does today's traffic still look like the training data, and does the label still mean the same thing? |

Plus 8 automatic fixes (`vigia fix`; the original file is never modified and
rows with doubtful labels are quarantined, not deleted), a before/after model
comparison, profiles for five public datasets (six profiles), and readers for CSV, Parquet,
Zeek, Suricata EVE and PCAP. It ships as a CLI, a Python library, a REST API
and a web dashboard (one Docker image).

Every finding carries a severity, a metric, the affected rows, concrete
examples and a recommendation. A check that cannot run says so: the report
turns **grey**, not green, because "found nothing" and "clean" are different
things.

## Install

```bash
pip install vigia-nids            # core: CLI, readers, most checks
pip install "vigia-nids[ml]"      # label noise, near-duplicates, poisoning, concept drift
pip install "vigia-nids[api]"     # REST API and dashboard (vigia serve)
```

Python 3.11 or newer. Usage, Python API and options:
[`vigia/README.md`](vigia/README.md) and [`vigia/docs/USO.md`](vigia/docs/USO.md).

## Status and honest caveats

Version 1.0.3, on PyPI. 428 tests, CI on Linux and Windows with Python 3.11 to
3.13. Before the release the code went through an audit (50 findings, 1
critical), fixes and a verification. **All of it was done with Claude
(Anthropic), with no human reviewer, so it is not an independent audit.** The
reports, the prompts and the test for every fix are in
[`auditoria-1.0/`](auditoria-1.0/).

Known limits, stated rather than hidden:

- The production deployment (Caddy, HTTPS, Docker Compose) has only been
  tested locally, never on a real server.
- The new `drift.concept` is calibrated on synthetic data only.
- The CIC-IDS2017 random-split figures are unstable: 9 changed values out of
  3.1 M rows moved F1 from 0.20 to 0.39. Over 10 seeds the random-split recall
  of one attack ranges from 0 to almost 1, and the ranges with and without the
  identifier columns overlap, so that comparison cannot be concluded. Only the
  temporal-split result holds (0.00 recall in all 10 seeds). Details in
  [`RESULTADOS.md`](vigia/benchmarks/RESULTADOS.md).
- Three requirements are only partly met: shortcut detection (R5) and session
  leakage (R6) are simpler than the design asks, and clean-label poisoning is
  not detected. See [`vigia/docs/PLAN.md`](vigia/docs/PLAN.md).
- The API isolates nothing between clients that share the key and has no
  per-job time limit: give the key only to people you trust.

Full list: [`vigia/docs/PLAN.md`](vigia/docs/PLAN.md).

## Datasets and citation

The benchmarks audit public datasets that are not redistributed here. If you
use CIC-IDS2017, please cite its authors:

> Iman Sharafaldin, Arash Habibi Lashkari and Ali A. Ghorbani. *Toward
> Generating a New Intrusion Detection Dataset and Intrusion Traffic
> Characterization.* 4th International Conference on Information Systems
> Security and Privacy (ICISSP), 2018.

The corrected version used in the validation comes from:

> Gints Engelen, Vera Rimmer and Wouter Joosen. *Troubleshooting an Intrusion
> Detection Dataset: the CICIDS2017 Case Study.* IEEE Security and Privacy
> Workshops (SPW), 2021. doi:10.1109/SPW53761.2021.00009

To reproduce the results, see
[`vigia/docs/REPRODUCIR.md`](vigia/docs/REPRODUCIR.md): where each dataset comes
from, the folder layout, and one command per result.

To cite Vigía itself, use the "Cite this repository" button (`CITATION.cff`).

## Repository layout

| Path | Contents |
|---|---|
| [`vigia/`](vigia/) | The package: code, tests, docs, benchmarks, web dashboard, Docker and deployment files |
| [`auditoria-1.0/`](auditoria-1.0/) | The pre-release audit, its verification and the prompts used |
| [`vigia.md`](vigia.md) | The original design document (September 2026) |

## Contributing and security

Bug reports, false positives and false negatives on real datasets are the most
useful contributions. See [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a
vulnerability, please do not open a public issue: see
[`SECURITY.md`](SECURITY.md).

## License

[Apache 2.0](LICENSE).
