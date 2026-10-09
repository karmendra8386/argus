"""Gateway configuration: providers, tiers, and runtime settings.

Providers are declared in code (or loaded from a dict); API keys come from
the environment. Prices are tokenecon ModelTiers so routing and costing share
one source of truth.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List

from tokenecon import ModelTier

from .providers.base import Provider


@dataclass
class ProviderEntry:
    """One backend behind the gateway."""

    provider: Provider
    tier: ModelTier
    models: List[str]  # model names this backend serves, e.g. ["gpt-4o-mini"]
    enabled: bool = True


@dataclass
class GatewayConfig:
    db_path: str = os.environ.get("AIGW_DB", "aigw.db")
    master_key: str = os.environ.get("AIGW_MASTER_KEY", "sk-admin-changeme")
    default_budget_usd: float = float(os.environ.get("AIGW_DEFAULT_BUDGET", "10.0"))
    default_budget_mode: str = os.environ.get("AIGW_BUDGET_MODE", "degrade")  # degrade | hard
    safety_margin: float = 0.1  # tier-selection margin, mirrors tokenecon router
    providers: List[ProviderEntry] = field(default_factory=list)

    def models(self) -> List[Dict[str, str]]:
        """Model catalog in OpenAI /v1/models shape."""
        out = []
        for entry in self.providers:
            if not entry.enabled:
                continue
            for m in entry.models:
                out.append({"id": m, "object": "model", "owned_by": entry.provider.name})
        return out

    def entry_for_model(self, model: str) -> ProviderEntry | None:
        for entry in self.providers:
            if entry.enabled and model in entry.models:
                return entry
        return None
