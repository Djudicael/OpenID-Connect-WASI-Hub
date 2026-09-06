---
name: update-project-docs
description: Keep OpenID Connect WASI Hub documentation synchronized with implemented behavior. Use after feature, API, configuration, deployment, UI, or security changes, and when creating or refreshing human-facing guides and screenshots under docs/.
---

# Update project documentation

Document verified behavior from the current working tree. Do not describe planned or partially wired behavior as available.

## Discover the affected documentation

1. Read `AGENTS.md`, `README.md`, relevant files under `docs/`, and the changed code and migrations.
2. Inspect `git status --short` and preserve unrelated user work.
3. Map the change to every affected surface: user guide, administrator guide, API reference, configuration, deployment, security notes, and feature/gap matrices.
4. Prefer one canonical explanation and link to it from shorter summaries instead of duplicating long instructions.

## Write for human operators

- Put task-oriented guides under `docs/` and organize them around outcomes such as creating an organization, inviting a member, or configuring an identity provider.
- Include prerequisites, exact UI navigation, expected results, and recovery guidance for likely failures.
- Keep endpoint names, JSON fields, environment variables, defaults, and security consequences consistent with the implementation.
- Distinguish administrator actions from end-user actions and native-only behavior from WASI behavior.
- Use relative Markdown links inside repository documentation.

## Screenshots

Capture screenshots only from a working build containing the documented feature. Use the repository's Playwright setup when practical so captures are repeatable.

- Store images under `docs/assets/<guide-name>/` with stable, descriptive lowercase names.
- Use a deterministic viewport, seeded non-sensitive sample data, and a clean browser state.
- Exclude passwords, tokens, API keys, cookies, connection strings, personal data, and machine-specific paths.
- Capture the smallest useful screen area while retaining enough surrounding UI for orientation.
- Add meaningful alt text and keep every referenced image checked into the repository.
- Refresh a screenshot when the visible workflow or labels change; do not refresh images for invisible backend-only changes.

## Validate

1. Build the relevant backend and frontend before documenting UI behavior.
2. Exercise every documented workflow, using Playwright for screenshot-based guides.
3. Check that local links and image paths resolve, commands match the current toolchain, and examples contain no secrets.
4. Run `git diff --check` and review the complete documentation diff for stale claims.
5. Report which guides and screenshots changed and any workflow that could not be exercised.
