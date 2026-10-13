# Release Engineering Guide

## Inputs

Use the exact prior release tar archive as the patch base. Verify its hash when
available. Do not reconstruct a base tree from memory or an unrelated working
directory.

## Release sequence

1. Extract the prior archive into a clean base tree.
2. Create a separate working tree.
3. Implement source, tests, configuration, examples, docs, and changelog.
4. Run focused tests while developing.
5. Verify release dependency constraints and create/check the site lockfile.
6. Run the complete test and compile gates.
7. Generate a patch from the exact base to the release tree.
8. Apply the patch to another fresh base extraction.
9. Compare patched and staged trees by content.
10. Build a source archive with one versioned top-level directory.
11. Extract the archive, compare contents, and rerun release tests.
12. Generate checksums, a machine-readable manifest, and a validation report.

## Dependency reproducibility

Published project and development dependencies declare supported minimums so
packaging metadata does not impose an artificial upper cap. Release-managed uv
environments use exact versions under `[tool.uv].constraint-dependencies` and
`build-constraint-dependencies`. Mirror those selections in the versioned file
under `constraints/` and test that both sources remain identical.

After extracting a release, the maintainer runs `uv lock` and then
`uv sync --all-groups --locked` on the supported release platform. Record the
uv, Python, and operating-system versions used. A dependency upgrade is a
release change: update the constraints, regenerate the lock, and rerun static
analysis,
tests, archive validation, and production replay. Ordinary operators continue
to use `--no-sync`.

For a Linux release, the versioned constraint file identifies the exact package
set validated on Linux. It must not retain a `sys_platform == 'win32'` entry or
turn a Windows-only package such as Colorama into an unconditional/Linux
requirement. Add a Linux marker only when a dependency is genuinely Linux-only;
platform-neutral packages do not receive decorative markers. A regression test
must compare the text manifest with the concatenated runtime/build uv arrays and
reject any Windows marker. Generate/check the lock on Linux in the connected
maintainer environment.

## Artifact exclusions

Do not package:

```text
.git/
.venv/
.pytest_cache/
__pycache__/
*.pyc
build/
dist/
*.egg-info/
```

## Changelog discipline

Describe behavior introduced, corrected, or retired by the release. Mention a
schema number only when that schema changes; the current-version inventory
belongs in [`SCHEMA.md`](SCHEMA.md). Do not pad a new entry by restating an
established feature from several releases earlier. A brief reminder is useful
only when it explains a direct dependency, compatibility boundary, or operator
impact of the current change.

Keep historical entries intact except for factual or editorial corrections.
Release-specific validation results belong in the validation report rather than
being repeated as enduring product behavior.

## Release report

State exactly which checks passed, failed, or were not available. Include base
and artifact hashes, test counts, schema versions, archive-root validation, and
any limitation of the validation environment.
