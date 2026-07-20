# Contributing to remedify

Thanks for looking at remedify. It's a **last-mile vulnerability remediation planner**:
it turns scanner output (Trivy / Grype / OSV / Sysdig) into the exact, deterministic
commands to actually fix each finding — no guessing, no "ask an AI to invent a fix".

## Before you start: honest expectations

- **remedify is maintained by one person** (bus factor: 1). Responses are best-effort
  and may take days, sometimes longer. I'd rather tell you that up front than leave an
  issue silent.
- **Correctness comes first.** This is a security tool, so bugs where remedify could
  *silently drop a finding* or *emit a wrong command* are triaged ahead of features.
- **Non-goal:** remedify never auto-applies patches. It plans; humans (or their CI) decide.
  PRs that cross that line won't be merged.

## Ways to contribute

- **Good first issues:** look for the [`good first issue`](https://github.com/higakikeita/remedify/labels/good%20first%20issue)
  label. These are scoped and have a maintainer to guide you.
- **Report a bug:** include the scanner, the input file (anonymized is fine), the command
  you ran, and what you expected vs got. A failing input is the most useful thing you can send.
- **Add a scanner or distro:** see the parser template ([#14](https://github.com/higakikeita/remedify/issues/14)).
  The contract is a normalized finding; match an existing parser (`parse_trivy` / `parse_grype`)
  as your model.

## Development

- Python, **single file, standard library only** (zero dependencies). Keep it that way —
  it's a design promise (`scp remedify.py` and it runs anywhere).
- Run the tests before opening a PR:
  ```bash
  python -m unittest discover -s tests -v
  ```
- New behavior needs a regression test. Correctness fixes especially: add a test that
  fails before your fix and passes after.
- Keep the CLI deterministic. LLM/BYO-key paths are opt-in and must never be required for
  core output.

## License

By contributing you agree your contribution is licensed under Apache-2.0 (the project license).

## Conduct

Be kind. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
