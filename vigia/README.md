# Vigía

**English** · [Español](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/README.es.md)

**Continuous quality control for the datasets behind cybersecurity models.**

Vigía audits the datasets used to train intrusion detectors and answers an
uncomfortable question: *is this 0.99 F1 real, or an artifact of the data?*

Research on the most widely used datasets in the field (CIC-IDS2017,
CSE-CIC-IDS2018, UGR'16) documents massive duplicates, wrong labels, leakage
between training and test sets, and columns that give the answer away to the
model. The result is always the same: **the model looks excellent in the lab and
fails on a real network.**

> Status: **v1.0.4, public beta.** All three modules are implemented and have
> been run against real data. The auditor covers the P0 requirements of the
> design (R1 to R10) with five exceptions (R5, R6, R7, R8 and `labels.window`),
> described under "Known limits" in
> [`docs/PLAN.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/PLAN.md).
> It also ships readers for Zeek, Suricata EVE and PCAP, a REST API, a web
> dashboard and a Docker image. Four of the five drift checks have been measured
> on the five days of CIC-IDS2017 (`drift.concept` was rebuilt before release and
> is only calibrated on synthetic data); the poisoning detectors on attacks
> injected into that same traffic and on the label noise documented by Engelen et
> al.; and the auditor on the 10 files (16.2 M rows) of CSE-CIC-IDS2018. The
> numbers are in
> [`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md),
> including the cases where performance is poor. Clean-label poisoning is not
> detected. The pre-release audit was done entirely with Claude, with no human
> reviewer, so it is not independent.
>
> **Most of the documentation is in Spanish.** This README is the exception.

## The three modules

| Module | Command | Question it answers |
|---|---|---|
| **1. Audit** | `vigia audit` | Does this dataset have defects that inflate the metrics? |
| **2. Poisoning** | `vigia poison` | Did someone insert records to manipulate the model? |
| **3. Drift** | `vigia drift` | Does today's traffic still look like the training data? |

25 checks (16 for the audit, 4 for poisoning and 5 for drift), 8 automatic fixes
and a before/after performance comparison.

## Install

```bash
pip install vigia-nids                # core: CLI, readers and most checks
pip install -e ".[dev]"               # or, from the repository
vigia --help
```

Requires Python 3.11 or newer. Optional extras, depending on what you need:

| Extra | What it adds |
|---|---|
| `[ml]` | `labels.noise` (cleanlab), `dup.near` (datasketch), `poison.loss`, `poison.knn`, `poison.cluster`, `drift.covariate` and `drift.concept` (scikit-learn), and the before/after comparison (LightGBM) |
| `[parquet]` | Installs `pyarrow`. Not needed to read or write `.parquet`: Polars does it without it |
| `[api]` | REST API and web dashboard (`vigia serve`) |
| `[pcap]` | Extract flows from a PCAP (NFStream) |

Without `[ml]` the checks that need it do not fail: they show up under "checks
not run", with the command to install what is missing.

## Usage

```bash
# Audit a dataset (columns are detected by name)
vigia audit data/flows.csv --report out/

# Use the profile of a known dataset (sets the columns for you)
vigia audit data/cic2017.csv --profile cic-ids-2017

# State the columns explicitly
vigia audit data/flows.parquet \
  --label-col Label --split-col split --time-col Timestamp \
  --src-ip-col "Src IP" --dst-ip-col "Dst IP" \
  --report out/

# Run only one category of checks
vigia audit data/flows.csv --checks leak,dup

# In CI: exit with code 1 if there are critical findings
vigia audit data/train.csv --fail-on critical

# List the available checks
vigia checks
```

From Python:

```python
import vigia

ctx = vigia.load("data/flows.parquet", label_col="Label", split_col="split")
report = vigia.audit(ctx)

print(report.traffic_light())  # 'rojo' | 'amarillo' | 'verde' | 'gris'
print(report.counts())  # {'critical': 2, 'high': 1, ...}

from vigia.report import write_report

write_report(report, "out/")  # report.html + report.json
```

The traffic-light values are Spanish words: `rojo` (red), `amarillo` (yellow),
`verde` (green) and `gris` (gray).

## Profiles of known datasets

`--profile` (or `vigia.load(..., profile=...)`) loads verified metadata for a
public dataset: label, time and IP columns, documented attackers and attack
windows, and known errors. A column passed by hand always wins over the profile.

| Profile | Dataset | What it carries |
|---|---|---|
| `cic-ids-2017` | CIC-IDS2017 | columns, 14 attack windows, known errors |
| `cse-cic-ids-2018` | CSE-CIC-IDS2018 | columns (confirmed on the CSVs), 22 windows, real labels, observed problems |
| `unsw-nb15` | UNSW-NB15 (training and testing) | labels, 9 categories, attackers, victims and capture sessions from the official ground truth |
| `unsw-nb15-raw` | UNSW-NB15 (4 raw CSVs) | the 49 column names, since those files have no header |
| `ugr-16` | UGR'16 | attack calendar, captures, anonymized IPs, labels |
| `ctu-13` | CTU-13 | 13 malware scenarios, infected hosts and duration; label format |

Every value comes from the dataset's official documentation; what the source
does not publish is not invented. Three warnings:

- `ugr-16`: the format (headerless CSV, 13 columns) was confirmed only on a
  5,000-row third-party sample, because the official site was unavailable; the
  column names are the paper's and `label` is a convention of the profile.
- `cse-cic-ids-2018`: `Timestamp` uses a 12-hour clock without AM/PM, so the
  profile does not set it as the time column.
- `ctu-13`: the label has dozens of subtypes per scenario, so the profile groups
  it into botnet, to_botnet, normal and background (`label_groups`) and keeps
  the original in `__label_original`. A profile of your own can do the same.

`vigia audit` shows the profile's known errors when it runs. The results of
auditing these datasets are in
[`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md).

## API and web dashboard

```bash
pip install -e ".[api]"
export VIGIA_API_KEY="a-long-random-key"
vigia serve                      # API at http://localhost:8000

# or, with the dashboard included, in a single container:
VIGIA_API_KEY=a-key docker compose up --build
```

Without `VIGIA_API_KEY` the API runs **without authentication**: do not leave it
that way outside a development machine (with `VIGIA_ENV=production` it refuses to
start). To put it on a server with HTTPS, see
[`docs/DESPLIEGUE.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/DESPLIEGUE.md).
The API only accepts CSV and Parquet (a PCAP gets a 415), limits the upload size,
deletes the dataset when the job ends and runs as an unprivileged user in Docker.
It isolates nothing between clients that share the key and has no per-job time
limit: give the key only to people you trust. Full reference in
[`docs/USO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/USO.md#api-rest).

## What it checks today

| Check | What it finds |
|---|---|
| `dup.exact` | Identical rows: the model is evaluated on examples it has already seen |
| `dup.class_ratio` | Classes made up mostly of duplicates |
| `dup.cross_split` | **Critical.** The same row in training and in test |
| `dup.near` | Near-identical rows that `dup.exact` misses (MinHash); above 200,000 rows it reviews a sample |
| `leak.temporal` | The test set overlaps the training set in time |
| `leak.host` | The same attacker host in both splits: the model memorizes the IP |
| `shortcut.single_feature` | A single column predicts the label too well |
| `shortcut.identifier` | IPs, flow IDs or timestamps used as features |
| `validity.nan_inf` | NaN and infinities (CIC-IDS2017 has them in the rate columns) |
| `validity.constant` | Columns with a single value |
| `validity.impossible` | Ports > 65535, negative durations, negative bytes |
| `validity.column_names` | Names with spaces (`" Destination Port"`) or ambiguous ones |
| `leak.session` | Flows of the same connection split across sets |
| `labels.conflict` | Identical rows with different labels |
| `labels.noise` | Labels that contradict the rest of the dataset (cleanlab); it does not report below 0.1 % and states how much it may have overestimated |
| `labels.taxonomy` | The same class written in several ways |
| `labels.imbalance` | Classes with so few examples that their metric says nothing |

**Known limits of the checks.** `shortcut.single_feature` measures the balanced
accuracy of a "majority class per value" rule on the same rows it computes it
on (no holdout), and only reports columns above the threshold, not a model
trained on each column. `leak.session` groups by 5-tuple without a time window:
a tuple reused weeks later counts as the same session. The full list is in
[`docs/PLAN.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/PLAN.md).

**Role columns.** The time and IP columns you declare (with `--time-col`,
`--src-ip-col`, `--dst-ip-col` or a profile) are treated as metadata:
`shortcut.identifier` does not flag them and they do not count when deciding
whether two rows are duplicates, so the same flow seen from another IP or at
another time is detected as a duplicate. They remain available to
`shortcut.single_feature` and to the leakage checks, which are the ones that find
an IP giving the label away. Columns detected only by name are treated as
possible identifiers.

Every finding carries a severity, a metric, the affected rows, concrete examples
and a recommendation. A check that cannot run (the split column is missing, for
example) does not fail silently: it appears in the "checks not run" section of
the report.

### The traffic light

| Color | Meaning |
|---|---|
| **red** | There are critical or high findings, or a check failed with an internal error |
| **yellow** | There are medium or low findings |
| **green** | No findings and every check ran |
| **gray** | No findings, but some checks did not run |

Gray exists because "I found nothing" and "it is clean" are not the same thing.
If the label or split column is not detected, the checks that get skipped are
precisely the ones that look for leakage and duplicates across sets: returning
green there would confirm that the dataset is fine when it was hardly reviewed.
If the light is gray, specify the columns by hand with `--label-col` and
`--split-col`.

## Fixing

Findings name their fix. `vigia fix` applies them:

```bash
# See the available ones
vigia fixes

# Apply them in a chain; the original file is never touched
vigia fix data/flows.csv \
  --apply drop_duplicates,drop_constant,drop_identifiers \
  --out data/flows_fixed.parquet
```

Rows with doubtful labels are **never deleted**: `quarantine_noise` puts them in
a separate file for a person to review.

## Measuring how much of the performance was real

```python
from vigia.benchmark import compare

c = compare(ctx, ["drop_identifiers"])
print(c.summary())
print(c.after.per_class_recall)
```

It trains the same model before and after fixing. A drop does not mean the fixes
made the model worse: it means the original number was inflated. On CIC-IDS2017,
switching a random split for a temporal one takes the recall of DoS Hulk,
PortScan and DDoS from a value that, with the random split, ranges between 0 and
almost 1 depending on the seed, to **0.00 in all 10 seeds tried**. See
[`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md).

## Input formats

| Format | Extension | Notes |
|---|---|---|
| CSV | `.csv`, `.txt` | Retries as cp1252 if it is not UTF-8 |
| Parquet | `.parquet`, `.pq` | Keeps the types |
| Zeek | `.log` | TSV with header or JSON Lines |
| Suricata EVE | `.json`, `.eve` | `--event-type` picks flows or alerts |
| PCAP | `.pcap`, `.pcapng`, `.cap` | With `pip install 'vigia-nids[pcap]'` |

A single file or a whole folder: CIC datasets come split into one file per day;
Vigía concatenates them and keeps the origin in `__source_file`. PCAPs are read
one at a time, because extracting flows takes minutes.

Details of each format in
[`docs/USO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/USO.md#formatos-de-entrada).

## Development

```bash
pip install -e ".[dev,ml]"

pytest                 # tests
ruff check src tests   # lint
ruff format src tests  # format
mypy src               # types
```

Adding a new check is a class with four attributes and one method. Registration
is automatic when the module is imported from `vigia/checks/__init__.py`. Details
in [`docs/ARQUITECTURA.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/ARQUITECTURA.md).

## Documentation (in Spanish)

| Document | What it is for |
|---|---|
| [`docs/CHECKS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/CHECKS.md) | What each audit finding means and what to do |
| [`docs/ENVENENAMIENTO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/ENVENENAMIENTO.md) | Module 2: the detectors, the simulator and how well they work |
| [`docs/DERIVA.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/DERIVA.md) | Module 3: the checks, the metrics and how to read them |
| [`docs/USO.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/USO.md) | CLI, SDK and JSON format reference |
| [`docs/DESPLIEGUE.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/DESPLIEGUE.md) | Putting the API and dashboard on a server: Caddy, variables, what to watch and the known limits |
| [`docs/ARQUITECTURA.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/ARQUITECTURA.md) | How it is built inside; how to add a check |
| [`docs/REPRODUCIR.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/REPRODUCIR.md) | How to reproduce the results: where each dataset comes from and one command per result |
| [`benchmarks/RESULTADOS.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/benchmarks/RESULTADOS.md) | Verified results: NSL-KDD, CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, CTU-13, the false-positive control and the calibration |
| [`docs/PLAN.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia/docs/PLAN.md) | Status, known limits, what is pending and the original phased plan |
| [`AUDITORIA-1.0.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/auditoria-1.0/AUDITORIA-1.0.md) | The pre-1.0 audit: 50 findings, how each was reproduced and fixed |
| [`VERIFICACION-1.0.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/auditoria-1.0/VERIFICACION-1.0.md) | The verification of those fixes and what it found. The same Claude session that wrote the fixes did it: it is not independent |

## Design document

The full design (the three modules, the architecture, the phased plan and the
academic references) is in
[`vigia.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/vigia.md).

## Contributing and security

The most useful reports are wrong findings: a false positive, or a real defect
Vigía missed, on a public dataset. There is a template for that in the
[issues](https://github.com/Joshua203-byte/vigia-nids/issues/new/choose). How to
set up the environment and the project conventions:
[`CONTRIBUTING.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/CONTRIBUTING.md).
To report a vulnerability, do not open a public issue: see
[`SECURITY.md`](https://github.com/Joshua203-byte/vigia-nids/blob/main/SECURITY.md).

## License

Apache 2.0.
