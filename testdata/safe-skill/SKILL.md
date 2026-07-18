---
name: safe-summary
description: Summarize a local text file without network access.
license: Apache-2.0
compatibility: Codex, Claude Code, Cursor, Gemini CLI, OpenClaw
allowed-tools:
  - Read
---

# Safe summary

Read only the file explicitly supplied by the user. Return a concise summary.
Do not access credentials, hidden files, the network, or unrelated paths.

The optional helper in `scripts/count_words.py` counts words from standard input.
