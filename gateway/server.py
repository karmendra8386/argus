"""FastAPI server: the security layer in front of every model.

Request path:
    auth -> INPUT policy engine -> budget -> route -> provider
                                          -> OUTPUT policy engine -> ledger/audit -> response

Budget behavior per key:
  - mode="hard":    429 once spend >= budget.
  - mode="degrade": past budget, requests fall back to the cheapest tier and
                    are flagged degraded=true instead of failing.
"""

from __future__ import annotations

import time
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .auth import KeyRecord, KeyStore
from .config import GatewayConfig
from .ledger import CallEntry, Ledger
from .providers.base import ChatMessage, ChatRequest, ProviderError
from .router import select_route
from .security.audit import AuditEvent, AuditLog
from .security.loader import load_profiles
from .security.policy import PolicyEngine, default_policy


def create_app(
    config: GatewayConfig,
    policy: PolicyEngine | None = None,
    policy_file: str | None = None,
    max_input_chars: int = 100_000,
) -> FastAPI:
    keys = KeyStore(config.db_path)
    ledger = Ledger(config.db_path)
    audit = AuditLog(config.db_path)
    if policy_file:
        profiles, default_profile = load_profiles(policy_file)
    elif policy:
        profiles, default_profile = {"standard": policy}, "standard"
    else:
        profiles, default_profile = {"standard": default_policy()}, "standard"
    app = FastAPI(title="argus", version="0.1.2")
    app.state.config = config
    app.state.keys = keys
    app.state.ledger = ledger
    app.state.audit = audit
    app.state.profiles = profiles

    def require_key(authorization: str | None = Header(default=None)) -> KeyRecord:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing Bearer API key")
        rec = keys.verify(authorization[7:])
        if rec is None:
            raise HTTPException(401, "invalid or revoked API key")
        return rec

    def require_admin(x_admin_key: str | None = Header(default=None)):
        if x_admin_key != config.master_key:
            raise HTTPException(401, "invalid admin key")

    def _audit_from_result(key_id, task_id, direction, result, action_filter=None):
        for tag in result.redactions:
            detector, _, category = tag.partition(":")
            audit.record(AuditEvent(key_id, task_id, direction, detector, category,
                                    "redact", result.text))
        for tag in result.flags:
            detector, _, category = tag.partition(":")
            audit.record(AuditEvent(key_id, task_id, direction, detector, category,
                                    "flag", result.text))

    @app.get("/v1/models")
    def list_models():
        return {"object": "list", "data": config.models()}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request, key: KeyRecord = Depends(require_key)):
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "invalid JSON body")
        messages_in = body.get("messages", [])
        if not messages_in:
            raise HTTPException(400, "messages is required")
        model_pin = body.get("model")
        task_id = request.headers.get("x-task-id")

        full_in = " ".join(m.get("content", "") for m in messages_in if isinstance(m, dict))
        if len(full_in) > max_input_chars:
            raise HTTPException(400, f"input exceeds {max_input_chars} chars")

        # --- security: input (per-key policy profile) ---
        engine = profiles.get(key.policy_profile) or profiles[default_profile]
        screened = engine.evaluate(full_in, "in")
        if screened.blocked:
            detector, _, category = screened.blocked.partition(":")
            audit.record(AuditEvent(key.id, task_id, "in", detector, category,
                                    "block", full_in))
            raise HTTPException(400, f"blocked by security policy: {screened.blocked}")
        _audit_from_result(key.id, task_id, "in", screened)
        if screened.text != full_in:
            # PII redacted: rewrite message contents with the redacted text.
            # (Per-message fidelity: re-run per message to keep mapping exact.)
            for m in messages_in:
                if isinstance(m, dict) and "content" in m:
                    m["content"] = engine.evaluate(m["content"], "in").text

        # --- budget ---
        spent = ledger.key_spend(key.id, key.period)
        over = spent >= key.budget_usd
        if over and key.mode == "hard":
            raise HTTPException(429, f"budget exhausted (${spent:.4f} >= ${key.budget_usd:.2f})")

        # --- route (degrade => cheapest tier) ---
        route = select_route(
            config,
            request_text=screened.text,
            model=None if model_pin in (None, "auto") else model_pin,
            force_cheapest=over,
        )
        degraded = route.degraded

        chat_req = ChatRequest(
            model=route.model,
            messages=[ChatMessage(role=m.get("role", "user"), content=m.get("content", ""))
                      for m in messages_in if isinstance(m, dict)],
            max_tokens=body.get("max_tokens"),
            temperature=body.get("temperature"),
        )
        try:
            resp = await route.entry.provider.chat(chat_req)
        except ProviderError as e:
            raise HTTPException(502, f"provider error: {e}")

        # --- security: output ---
        out = engine.evaluate(resp.text, "out")
        if out.blocked:
            detector, _, category = out.blocked.partition(":")
            audit.record(AuditEvent(key.id, task_id, "out", detector, category,
                                    "block", resp.text))
            raise HTTPException(502, f"blocked by security policy: {out.blocked}")
        _audit_from_result(key.id, task_id, "out", out)
        text = out.text

        # --- ledger ---
        cost = route.entry.tier.call_cost(resp.input_tokens, resp.output_tokens)
        ledger.record(CallEntry(
            key_id=key.id, task_id=task_id, provider=resp.provider,
            model=resp.model, tier=route.entry.tier.name,
            input_tokens=resp.input_tokens, output_tokens=resp.output_tokens,
            cost_usd=cost, degraded=degraded,
        ))

        security_flags = sorted(set(screened.flags + out.flags))
        return JSONResponse({
            "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": resp.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": resp.input_tokens,
                "completion_tokens": resp.output_tokens,
                "total_tokens": resp.input_tokens + resp.output_tokens,
            },
            "gateway": {
                "provider": resp.provider,
                "tier": route.entry.tier.name,
                "difficulty": round(route.difficulty, 3),
                "cost_usd": round(cost, 6),
                "degraded": degraded,
                "security": {
                    "redactions": sorted(set(screened.redactions + out.redactions)),
                    "flags": security_flags,
                },
            },
        })

    # ---------------- admin ----------------
    @app.post("/admin/keys", dependencies=[Depends(require_admin)])
    def admin_create_key(body: dict):
        profile = body.get("policy_profile", default_profile)
        if profile not in profiles:
            raise HTTPException(400, f"unknown policy profile {profile!r}")
        rec, raw = keys.create(
            name=body.get("name", "key"),
            budget_usd=float(body.get("budget_usd", config.default_budget_usd)),
            period=body.get("period", "monthly"),
            mode=body.get("mode", config.default_budget_mode),
            policy_profile=profile,
        )
        return {"id": rec.id, "name": rec.name, "key": raw,
                "budget_usd": rec.budget_usd, "period": rec.period,
                "mode": rec.mode, "policy_profile": rec.policy_profile}

    @app.get("/admin/profiles", dependencies=[Depends(require_admin)])
    def admin_profiles():
        return {"profiles": sorted(profiles.keys()), "default": default_profile}

    @app.get("/admin/spend", dependencies=[Depends(require_admin)])
    def admin_spend():
        return ledger.total_spend()

    @app.get("/admin/keys/{key_id}/spend", dependencies=[Depends(require_admin)])
    def admin_key_spend(key_id: int, period: str = "monthly"):
        return {"key_id": key_id, "period": period,
                "spend_usd": round(ledger.key_spend(key_id, period), 6)}

    @app.get("/admin/tasks/{task_id}", dependencies=[Depends(require_admin)])
    def admin_task(task_id: str):
        return ledger.task_spend(task_id)

    @app.get("/admin/audit", dependencies=[Depends(require_admin)])
    def admin_audit(limit: int = 100, key_id: int | None = None):
        return {"events": audit.recent(limit=limit, key_id=key_id)}

    return app


def run(host: str = "127.0.0.1", port: int = 4000):  # entry point: argus
    import os

    import uvicorn

    from tokenecon import DEFAULT_TIERS

    from .config import ProviderEntry
    from .providers.mock import MockProvider

    mock = MockProvider()
    cfg = GatewayConfig(providers=[
        ProviderEntry(provider=mock, tier=DEFAULT_TIERS[0], models=["mock-small"]),
        ProviderEntry(provider=mock, tier=DEFAULT_TIERS[2], models=["mock-large"]),
    ])
    policy_file = os.environ.get("AIGW_POLICY_FILE")
    uvicorn.run(create_app(cfg, policy_file=policy_file), host=host, port=port)
