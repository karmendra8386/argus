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

## Argus Chat — the demo

![Argus Chat demo](demo/demo.gif)

*One live session (Nov 9, 2026) through **Argus Chat**, the integrated
showcase front-end: a normal summary with its cost receipt, a PII-bearing
request answered with the redactions already in place, an AWS key blocked
before any model saw it, and a prompt injection flagged on the receipt.
Argus's own record for the session: **3 calls, 605 tokens, $0.000182**.
The local model was Llama 3.2 1B Instruct behind Ollama on a small CPU
VM, mapped to tokenecon's small tier — so the dollars are shadow prices
for comparability, not invoices. Full screenshots, the task record, the
audit excerpt, the reproduction script, and the honest disclosures
(including how the two earlier models behaved differently) are in
[`demo/`](demo/).*

## Works with

- **[tokenecon](https://github.com/karmendra8386/agentic-ai-token-economics)** — the cost engine inside Argus: tiered routing, graceful budgets, per-task receipts. Argus Chat is where it becomes visible — every answer carries its receipt.
- **[mcplens](https://github.com/karmendra8386/mcplens)** — runtime vetting for MCP tool servers, so tools are graded before they connect to anything behind this gateway. The TicketDesk server built for the Argus Chat demo grades **A (100/100)**; feeding the grade into Argus's allow/deny path is the next build step.
- **[Argus Lens](https://github.com/karmendra8386/argus-lens)** — the same don't-send-it-unguarded stance at the browser surface: Lens checks prompts before they are sent; Argus checks them at the gateway.
- **[agent-cost-mcp-server](https://github.com/karmendra8386/agent-cost-mcp-server)** — run costs exposed to agents over MCP, from the same tokenecon accounting.
- **[PersistAIBench](https://github.com/karmendra8386/persistbench-bench)** and **[Argus-Bench](https://doi.org/10.5281/zenodo.23877366)** — the benchmarks that score what flows through: persistence failures over long runs, and 264 frozen screening cases for the gateway layer itself.

**The connected set** — one thread through all of it: what an agent did, what it cost, and whether it should have been allowed. [Argus](https://github.com/karmendra8386/argus) · [tokenecon](https://github.com/karmendra8386/agentic-ai-token-economics) · [mcplens](https://github.com/karmendra8386/mcplens) · [agent-cost-mcp-server](https://github.com/karmendra8386/agent-cost-mcp-server) · [Argus Lens](https://github.com/karmendra8386/argus-lens) · [PersistAIBench](https://github.com/karmendra8386/persistbench-bench) · [Argus-Bench](https://doi.org/10.5281/zenodo.23877366)

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

## Tunable detection profiles

Detection is a dial, not a fixed setting. Findings carry a confidence,
and a profile decides how sure the gateway must be before it acts — and
whether a local LLM judge reviews what the patterns miss:

- **strict** — catch everything, accept false alarms: low confidence
  thresholds, injections blocked, judge always on with a low block bar.
- **balanced** *(default)* — patterns flag at medium confidence and up;
  the judge runs only on pattern misses and blocks only when confident.
- **quiet** — minimise false alarms: only high-confidence pattern
  findings act, injections are flagged never blocked, judge off.
- **standard** — the legacy action-only profile, unchanged.

The shipped `policy.yaml` carries all four profiles; assign one per
key with `policy_profile`. Judge settings (endpoint, model, bars) are
per-profile YAML, and the judge is any local OpenAI-compatible
endpoint. Measured on the frozen [Argus-Bench](https://doi.org/10.5281/zenodo.23877366)
corpus (264 cases; judge = local Qwen2.5-0.5B, Nov 2026):

| Profile | Attacks detected | Attacks blocked | Benign flagged | Benign blocked |
|---|---|---|---|---|
| patterns only (v1 baseline) | 15/204 (7.4%) | — | 7/60 (11.7%) | — |
| quiet | 10/204 (4.9%) | 0 | 1/60 (1.7%) | 0 |
| balanced | 155/204 (76.0%) | 140 | 34/60 (56.7%) | 27 |
| strict | 155/204 (76.0%) | 155 | 34/60 (56.7%) | 34 |

The dial works — quiet↔strict spans the range — and the measurement
also shows the current limit: the 0.5B judge's self-reported
confidence barely discriminates (it answers 0.9 or 1.0 on both
verdicts), so balanced and strict detect identically and differ only
in enforcement. A judge whose confidence separates is the next lever.


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

**Companion preprint**

> K. Pandey, "Your AI Agent Is Now an IAM Principal: Identity Architecture
> for Autonomous Agents," Zenodo, DOI
> [10.5281/zenodo.23199763](https://doi.org/10.5281/zenodo.23199763), 2026.

```bibtex
@misc{pandey2026iamprincipal,
  author       = {Pandey, Karmendra},
  title        = {Your AI Agent Is Now an IAM Principal: Identity
                  Architecture for Autonomous Agents},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.23199763},
  url          = {https://doi.org/10.5281/zenodo.23199763}
}
```

A `CITATION.cff` is included for automated citation tooling.
Write-up: [Every LLM Call Should Pass Through a Security Layer — Here's the Pattern](https://builder.aws.com/content/3KT003C7DNJxr4m20Bu4Teoqm2U/every-llm-call-should-pass-through-a-security-layer-heres-the-pattern) — AWS Builder Center

## License

MIT — Karmendra Pandey.
