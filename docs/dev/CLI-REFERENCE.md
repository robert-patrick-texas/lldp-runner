# Commands and Scripts for Contributors

The operator-facing command reference is [`../CLI.md`](../CLI.md). This file
focuses on where command behavior is implemented and what contributors must
update.

## Main Python command families

- `lldp-runner run`: coordinator-driven recursive or seed-only discovery.
- `lldp-runner get-neighbors`: active one-device probe.
- `lldp-runner show-neighbors`: read-only discovery query.
- `lldp-runner diff`: compatibility and graph-aware cross-run comparison.
- `lldp-runner watch`, `status`, `pause`: running-state control and display.
- `lldp-runner clean`, `purge`: retention maintenance.
- `lldp-runner validate-config`, `paths`, `explain-target`: configuration and
  runtime-location diagnostics.

## Script launchers

- `lrun-run`, `lrun-seedrun`: common discovery launch patterns.
- `lrun-get`, `lrun-show`, `lrun-diff`, `lrun-watch`: short operator wrappers.
- `lrun-checkconfig`, `lrun-paths`, `lrun-explain`, `lrun-dryrun`:
  configuration review.
- `lrun-clean`, `lrun-purge`: retention actions.
- `lrun-bundle-diff`: selects two runs, creates a JSON diff, makes coherent
  SQLite backups, excludes WAL/SHM sidecars, and builds one review tar archive.
- `bootstrap.sh`, `shared-setup.sh`, `svc-setup.sh`, `svc-remove.sh`: deployment
  helpers.
- `check.sh`: local project checks.
- `md-to-html.sh`: documentation conversion helper.

## Change checklist

When a command or option changes, update:

1. `cli.py` parser and validation;
2. defaults/config/config-generation text where applicable;
3. launcher scripts;
4. operator help and [`docs/CLI.md`](../CLI.md);
5. README examples;
6. tests for parsing, behavior, and packaging; and
7. [`CHANGELOG.md`](../../CHANGELOG.md).
