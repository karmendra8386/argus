# Argus — the security layer for all AI models

[![PyPI version](https://img.shields.io/pypi/v/argus-gateway.svg)](https://pypi.org/project/argus-gateway/)
[![PyPI downloads](https://img.shields.io/pypi/dm/argus-gateway.svg)](https://pypi.org/project/argus-gateway/)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.23427027-blue)](https://doi.org/10.5281/zenodo.23427027)

An OpenAI-compatible gateway that sits in front of **any** LLM — OpenAI,
Anthropic, Bedrock, Gemini, Mistral, vLLM, Ollama, anything with an
OpenAI-shaped endpoint — and enforces security policy before a model ever
sees your data.

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
action, redacted snippet. Raw PII and secrets never touch the audit trail.
`GET /admin/audit` for compliance review.

## Quickstart

```bash
pip install argus-gateway
export AIGW_MASTER_KEY="sk-admin-secret"
export OPENAI_API_KEY="..."
argus   # serves on 127.0.0.1:4000
```

Point any OpenAI client at it — one `base_url` change:

```python
import openai
client = openai.OpenAI(api_key="<virtual-key>", base_url="http://localhost:4000/v1")
```

Self-hosted models sit behind the same layer:

```python
from gateway.providers.generic import GenericProvider
# vLLM, Ollama, llama.cpp — any OpenAI-shaped endpoint
```

Every response carries what happened:

```json
"gateway": {
  "provider": "openai", "tier": "small", "difficulty": 0.17,
  "cost_usd": 0.000004, "degraded": false,
  "security": {"redactions": ["pii:EMAIL"], "flags": ["prompt_injection:INSTRUCTION_OVERRIDE"]}
}
```

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
  version = {0.1.1},
  doi = {10.5281/zenodo.23427027},
  url = {https://github.com/karmendra8386/argus},
  date = {2026-10-19}
}
```

A `CITATION.cff` is included for automated citation tooling.

## License

MIT — Karmendra Pandey.
