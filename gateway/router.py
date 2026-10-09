"""Tiered routing powered by tokenecon.

Each request is scored for difficulty; the cheapest tier whose capability
clears difficulty + margin wins. A caller can pin a model (bypassing tier
selection) or force the cheapest tier (budget degradation path).
"""

from __future__ import annotations

from dataclasses import dataclass

from tokenecon import difficulty_score

from .config import GatewayConfig, ProviderEntry


@dataclass
class Route:
    entry: ProviderEntry
    model: str
    difficulty: float
    degraded: bool = False  # True when budget forced the cheapest tier


def _cheapest(entries: list[ProviderEntry]) -> ProviderEntry:
    return min(entries, key=lambda e: e.tier.input_per_mtok + e.tier.output_per_mtok)


def select_route(
    config: GatewayConfig,
    request_text: str,
    model: str | None = None,
    force_cheapest: bool = False,
) -> Route:
    """Pick a provider entry + model for the request.

    Args:
        model: explicit model pin (skips tier selection).
        force_cheapest: budget-degradation path; ignores difficulty.
    """
    enabled = [e for e in config.providers if e.enabled]
    if not enabled:
        raise ValueError("no providers configured")

    if model:
        entry = config.entry_for_model(model)
        if entry is None:
            raise ValueError(f"model {model!r} not served by any provider")
        return Route(entry=entry, model=model, difficulty=0.0)

    if force_cheapest:
        entry = _cheapest(enabled)
        return Route(entry=entry, model=entry.models[0], difficulty=1.0, degraded=True)

    difficulty = difficulty_score(request_text)
    candidates = [
        e for e in enabled
        if e.tier.capability >= difficulty + config.safety_margin
    ] or [_cheapest(enabled)]  # fall back: cheapest rather than refuse
    # cheapest capable tier wins
    entry = min(candidates, key=lambda e: e.tier.input_per_mtok + e.tier.output_per_mtok)
    return Route(entry=entry, model=entry.models[0], difficulty=difficulty)
