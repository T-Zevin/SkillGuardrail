# Benchmark manifests

CSV is used deliberately so the corpus can be inspected, diffed, and reviewed
without a package manager. Every entry is a **candidate** until its report and
human-review record are published.

Required columns:

- `id`: stable corpus identifier;
- `source_repository`: canonical public repository URL;
- `source_commit`: immutable Git commit to resolve;
- `skill_path`: directory within the repository that must contain `SKILL.md`;
- `cohort`: high-level comparison cohort;
- `domain`: research domain used for stratification;
- `status`: `candidate`, `scanned`, `reviewed`, or `excluded`;
- `notes`: selection rationale or documented exclusion.

Do not replace a commit in place. Add a new manifest version when upstream
content changes.
