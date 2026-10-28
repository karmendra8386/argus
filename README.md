# Argus — a security layer for OpenAI-compatible LLM traffic

[![PyPI version](https://img.shields.io/pypi/v/argus-gateway.svg)](https://pypi.org/project/argus-gateway/)
[![PyPI downloads](https://img.shields.io/pypi/dm/argus-gateway.svg)](https://pypi.org/project/argus-gateway/)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.23427027-blue)](https://doi.org/10.5281/zenodo.23427027)

An OpenAI-compatible gateway that enforces security policy before a model
sees your data. Argus ships native OpenAI and Anthropic provider adapters,
and its generic adapter can sit in front of OpenAI-shaped endpoints such as
vLLM and Ollama. Bedrock, Gemini, and Mistral adapters are roadmap items,
not part of the current release.

Every request passes through the policy engine on the way in and on the way
out. Cost intelligence (tiered routing, graceful budgets, per-task
attribution) rides along via [tokenecon](https://pypi.org/project/tokenecon/),
but security is the product.

## The security layer

```
request -> auth -> INPUT policy -> budget -> route -> model
                                              -> OUTPUT policy -> audit -> response
```

**Pluggable detectors** (each scans, the policy decides):

| Detector | Catches | Default action |
|---|---|---|
| Secrets | AWS keys, private keys, GitHub/OpenAI tokens, `password = ...` | **block** — never reaches a model |
| PII | emails, phones, SSNs, credit cards, IPs | **redact** — `[REDACTED:EMAIL]`, request continues |
| Prompt injection | "ignore previous instructions", role overrides, system-prompt probes, known jailbreaks | **flag** — allowed but marked (one flag away from block) |
| Blocklist | your own regexes | **block** |

**Policy engine:** per-direction rules (`in` / `out` / `both`) with four
actions — `allow`, `redact`, `block`, `flag`. Add an ML-based detector later
by subclassing `Detector`; no other code changes.

**Customizable without code:** write `policy.yaml` with named profiles
(`strict`, `standard`, `permissive`, or your own), point the gateway at it
with `AIGW_POLICY_FILE`, and assign a profile per virtual key — one team's
keys block injections while another's only flag them. `GET /admin/profiles`
lists what's loaded.

**Audit log:** every decision recorded — timestamp, key, task, detector,
and action. Redacted PII is recorded in its redacted form; blocked events
from the secrets detector store `[REDACTED:SECRET]` instead of payload text.
`GET /admin/audit` for compliance review.

## Quickstart

This five-minute demo uses the built-in mock models, so it needs no
provider API key.

Install Argus, set a master (admin) key, and start the gateway:

```bash
pip install argus-gateway
export AIGW_MASTER_KEY="sk-admin-secret"
argus
```

`argus` serves on `127.0.0.1:4000` with `mock-small` and `mock-large`.
Leave it running and use a second terminal for the remaining commands.

In the second terminal, create a virtual key. The response contains the
raw key only once, so the commands below print it and save it in a shell
variable for the next calls:

```bash
export AIGW_MASTER_KEY="sk-admin-secret"
KEY_RESPONSE=$(curl -s -X POST http://127.0.0.1:4000/admin/keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $AIGW_MASTER_KEY" \
  -d '{"name":"demo","budget_usd":10}')
printf '%s\n' "$KEY_RESPONSE"
export AIGW_VIRTUAL_KEY=$(printf '%s' "$KEY_RESPONSE" | python3 -c 'import json, sys; print(json.load(sys.stdin)["key"])')
```

Send text containing a private-key header. Argus blocks it before the
mock model is called:

```bash
curl -i -X POST http://127.0.0.1:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIGW_VIRTUAL_KEY" \
  -d '{"model":"mock-small","messages":[{"role":"user","content":"Use this key: -----BEGIN RSA PRIVATE KEY-----"}]}'
```

The response is HTTP 400:

```json
{"detail":"blocked by security policy: secrets:PRIVATE_KEY"}
```

Now send an email address:

```bash
curl -s -X POST http://127.0.0.1:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIGW_VIRTUAL_KEY" \
  -d '{"model":"mock-small","messages":[{"role":"user","content":"Email me at jane@example.com"}]}'
```

The call returns HTTP 200. Its `gateway` object is:

```json
"gateway": {
  "provider": "mock", "tier": "small", "difficulty": 0.0,
  "cost_usd": 3e-06, "degraded": false,
  "security": {"redactions": ["pii:EMAIL"], "flags": []}
}
```

Finally, inspect the audit log:

```bash
curl -s "http://127.0.0.1:4000/admin/audit?limit=10" \
  -H "X-Admin-Key: $AIGW_MASTER_KEY"
```

Events are returned newest first. The email event's snippet is
`Email me at [REDACTED:EMAIL]`; the blocked private-key event has
category `PRIVATE_KEY`, action `block`, and snippet `[REDACTED:SECRET]`.

The packaged `argus` command is this mock-only demo. Real backends are
configured in code with the native OpenAI and Anthropic providers or with
`GenericProvider` for an OpenAI-shaped endpoint.

## Also inside: cost intelligence

- **Tiered routing** — requests scored for difficulty, cheapest capable tier wins
- **Graceful budgets** — over budget? Falls back to the cheapest tier and flags
  `degraded: true` instead of failing (hard-stop mode available)
- **Per-task attribution** — `X-Task-Id` groups an agentic run's turns into one
  costed task: `GET /admin/tasks/{id}`

## Admin API (`X-Admin-Key` required)

- `POST /admin/keys` — issue virtual keys with budgets (`degrade`/`hard`, daily/monthly)
- `GET /admin/spend`, `GET /admin/keys/{id}/spend` — spend tracking
- `GET /admin/tasks/{task_id}` — per-task cost breakdown
- `GET /admin/audit?limit=&key_id=` — security decisions

## Roadmap

Streaming (SSE), Bedrock/Gemini/Mistral adapters, semantic caching,
OTEL/Prometheus export, admin UI, SSO/RBAC, ML-based injection detector.

## Cite

If you use this software in your work, please cite it:

```bibtex
@software{pandey_argus_2026,
  author = {Pandey, Karmendra},
  title = {Argus},
  version = {0.1.2},
  doi = {10.5281/zenodo.23427027},
  url = {https://github.com/karmendra8386/argus},
  date = {2026-10-28}
}
```

A `CITATION.cff` is included for automated citation tooling.

## License

MIT — Karmendra Pandey.
