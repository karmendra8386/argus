# Contributing to Argus

Thanks for your interest in improving Argus, the security layer for LLM
traffic. Contributions of all sizes are welcome: bug reports, new
detectors, policy profiles, provider adapters, and documentation.

## Ground rules

- **Security posture first.** Argus is a security control. Changes that
  weaken a default (for example, downgrading a `block` to a `flag`, or
  loosening a built-in detector) need an issue discussion and maintainer
  agreement *before* code.
- **Never log the secret.** Detectors and the audit log must never record
  raw sensitive values — log the detector name, the action taken, and
  redacted context only. Tests must use public test fixtures (for example,
  the standard `4242 4242 4242 4242` test card number), never real
  credentials or real personal data.
- **Policies are data, not code.** Behaviour that a deployment should be
  able to tune belongs in a policy profile (YAML), not hard-coded.
- **Python 3.9+.** Code must run on every supported version.

## Reporting bugs and requesting features

Open an issue at https://github.com/karmendra8386/argus/issues with:

- what you ran (request shape, policy profile in use) and what you
  expected,
- what actually happened, including the audit-log entry if relevant,
- your Python version and Argus version (`pip show argus-gateway`).

For a suspected false positive or false negative in a detector, include a
minimal example input — sanitised, with any real sensitive values replaced
by look-alikes.

## Development setup

```bash
git clone https://github.com/karmendra8386/argus.git
cd argus
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
```

## Running the tests

```bash
python -m pytest tests/ -q
```

The suite runs fully offline against the built-in mock adapter — no API
keys or live model calls needed. New behaviour must come with tests in
the same style, and the full suite should pass before you open a pull
request.

## Pull requests

1. Fork the repository and create a topic branch.
2. Keep the change focused; unrelated refactors belong in separate PRs.
3. Add or update tests for behaviour changes, and update the README if
   the public API, policy format, or documented behaviour changes.
4. For a new detector: include true-positive and false-positive cases,
   and state the action (`allow` / `redact` / `block` / `flag`) it takes
   under each built-in profile.
5. In the PR description, state the problem, the change, and how you
   tested it.

Maintainer review is by the project author; expect questions on security
posture before merge. Response times are best-effort — this is a
single-maintainer project.

## License

By contributing, you agree that your contributions are licensed under the
MIT License (see `LICENSE`).
