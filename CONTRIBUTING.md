# Contributing to remedify

Thanks for your interest! remedify is early-stage — the fastest way to help
is to try it against your own scan results and file an issue with anything
that breaks or reads wrong.

## Ways to contribute

- **Bug reports**: attach the (sanitized) scanner JSON that triggered it
- **New distro generators**: each package manager is a small function in
  `remedify.py` — see `fix_command()`
- **New scanner parsers**: Grype and Sysdig report parsers are the top
  roadmap items (see BACKLOG.md)
- **Real-world validation**: run it on production scan output and tell us
  where the commands or backport notes are wrong

## Development

```bash
git clone <repo> && cd remedify
python3 -m unittest discover tests -v      # run tests
python3 remedify.py examples/trivy-ubuntu.json   # smoke test
```

No dependencies. Please keep it that way for the CLI core — stdlib only.

## Pull requests

- One logical change per PR
- Add or update a test in `tests/`
- Update BACKLOG.md if you close an item

## Conduct

Be kind. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
