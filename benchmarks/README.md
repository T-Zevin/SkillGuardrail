# Scientific Skill Benchmark

This directory defines a reproducible, research-focused evaluation corpus for
SkillGuardrail. It is intentionally separate from the unit-test fixtures:

- **fixtures** prove that a rule fires or stays quiet under controlled input;
- **benchmark candidates** are real, public research skills selected for
  coverage and later human review;
- **published results** may only be generated from a pinned manifest and saved
  scan reports.

## v0.1 scope

`manifests/scientific-100.csv` is a 100-skill, domain-stratified seed corpus.
All entries point to individual directories in
[`K-Dense-AI/scientific-agent-skills`](https://github.com/K-Dense-AI/scientific-agent-skills)
at commit `ab2f84ab10597c59fac186ecda6d5edd5dcc8b92`.

The corpus prioritizes research workflows relevant to computational biology and
biomedicine while retaining adjacent scientific work: genomics, single-cell and
omics analysis, clinical research, cheminformatics, laboratory operations,
scientific literature, imaging, and reproducible data workflows.

The file is a **candidate manifest**, not an assertion that any publisher or
package is malicious, safe, endorsed, or compatible with every Agent host.

## Evaluation protocol

1. Resolve the exact repository commit recorded in the manifest.
2. Materialize only the recorded `skill_path`; do not silently scan another
   sibling skill in a multi-skill repository.
3. Scan the materialized directory with a recorded SkillGuardrail version and
   explicit limits.
4. Store the original JSON report, source fingerprint, command, timestamp, and
   source commit under `benchmarks/results/<run-id>/`.
5. Independently review all `review`, `block`, and `critical` verdicts. Record
   whether a finding is expected functionality, a documentation-quality issue,
   a confirmed policy concern, or unresolved.
6. Publish aggregate counts only after the raw reports and review ledger are
   available.

## What we will report

For every released benchmark snapshot we will publish:

- total candidate, completed, failed, and excluded sample counts;
- exact source commits, scanner version, command, limits, and run date;
- `pass` / `review` / `block` / `critical` distribution;
- distinct rule-signal and capability frequencies;
- file and content coverage;
- manual-review disposition for every non-pass verdict.

We will **not** equate a rule hit, risk score, `block` verdict, or capability
with malicious intent. A static scan cannot prove a skill safe or malicious.

## Status vocabulary

| Field | Meaning |
| --- | --- |
| `candidate` | Included for future pinned scanning; not yet an evaluated result. |
| `scanned` | JSON report is available, but manual review may still be pending. |
| `reviewed` | A human has recorded a review disposition. |
| `excluded` | Excluded with a documented reason; never silently dropped. |

## Initial composition

| Cohort | Count | Purpose |
| --- | ---: | --- |
| Omics, genomics, and bioinformatics | 28 | Stress scripts, packages, data formats, and workflow references common in biomedical research. |
| Clinical, chemistry, and laboratory research | 19 | Cover sensitive-domain integrations, database clients, modeling, and lab automation. |
| Literature and scientific writing | 15 | Cover web lookup, document handling, citations, and scientific communication. |
| Research operations | 11 | Cover research search, notebooks, compliance, and supporting workflows. |
| Scientific computing, imaging, and cross-disciplinary analysis | 27 | Provide adjacent research workflows and diverse dependency patterns. |

## Next cohorts

The v0.1 corpus deliberately starts from a single pinned upstream repository so
that every entry has a stable taxonomy. v0.2 will add independent sources,
including biomedical skill collections, literature-review skills, and the
project's own cfDNA skills. These sources will be reported as separate cohorts;
their results must not be merged without preserving source provenance.
