# Benchmark Roadmap: 1,100+ Public Agent Skills

## Goal

Build a reproducible, cross-domain Agent Skill security corpus large enough to
measure rule behavior, capability patterns, and false-positive burden without
mistaking one publisher's conventions for the entire ecosystem.

The corpus is an evaluation set, not a reputation list. No aggregate result
may label a publisher, package, or domain malicious.

## Target allocation

| Cohort | Target | Examples of intended coverage |
| --- | ---: | --- |
| Biomedical and scientific research | 280 | Bioinformatics, omics, clinical research, lab automation, cheminformatics, imaging, scientific computing. |
| Social science, literature, and academic work | 170 | Systematic review, citation work, research design, qualitative analysis, survey/data workflows, manuscript review and response. |
| Software engineering and DevOps | 280 | Code review, testing, CI/CD, cloud, infrastructure, web development, security, package management. |
| Machine learning, data, and AI | 170 | Model evaluation, MLOps, RAG, data engineering, visualization, GPU workflows, AI research. |
| Quantitative finance and economic analysis | 100 | Market data, backtesting, portfolio/risk analysis, financial reporting, macroeconomic and business research. |
| Cross-domain professional automation | 100 | Documents, spreadsheets, presentations, knowledge management, web research, project operations. |
| **Total** | **1,100** | Minimum release target. |

The current 108-skill v0.1 pilot contributes 55 biomedical/life-science skills
and 53 adjacent scientific/research-workflow skills. It is not yet a published
result set.

## Source-diversity rules

1. No single repository may contribute more than 25% of the final corpus.
2. Every major cohort must contain at least five independent publishers or
   collections where public sources exist.
3. A multi-skill repository is recorded as one **source cluster** even when it
   contributes many individual skill directories.
4. Aggregate reports must show both per-skill and per-source-cluster summaries.
5. Every entry must record a canonical repository URL, immutable commit, skill
   path, domain, and selection rationale.

## Inclusion and exclusion

Include only public, inspectable packages with a `SKILL.md` or a documented
equivalent that can be mapped to the Agent Skills format. Exclude duplicates,
archived repositories with inaccessible source, generated mirrors that duplicate
the upstream package, and packages that cannot be pinned to a commit.

Potentially malicious samples are handled separately as **de-weaponized test
fixtures**. They are never mixed into the public-skill prevalence statistics.

## Release gates

A benchmark snapshot may be published only when all of the following are true:

- every included item resolves to its recorded commit and path;
- its scan report records the exact SkillGuardrail version and limits;
- incomplete scans and exclusions are counted, not discarded;
- every non-pass report has a manual-review disposition;
- per-domain and per-source-cluster distributions accompany any global total;
- the report states that rule hits and verdicts are not evidence of malicious
  intent or a probability of compromise.

## Candidate source families

The first research pilot draws from K-Dense Scientific Agent Skills and cfDNA
Skills. Candidate expansion sources include public Agent Skills collections from
NVIDIA, Anthropic, Microsoft, Vercel, engineering-workflow collections, and
independent research-skill catalogs. Candidate sources are not automatically
endorsed or included; each must satisfy the pinning and provenance rules above.

## Execution phases

1. **Pilot (108)** — validate manifest schema, category language, report
   storage, and manual-review ledger.
2. **Expansion (300)** — add independent biomedical, literature, and engineering
   source clusters; validate subdirectory acquisition for multi-skill repos.
3. **Cross-domain (700)** — add ML/data and quant-finance cohorts with balanced
   source representation.
4. **Release corpus (1,100+)** — run the locked manifest, complete manual review,
   publish raw JSON reports and an aggregate methodology report.
