"""YAML policy profiles: name a posture, assign it to a key.

Example policy.yaml:

    default_profile: standard
    blocklist_patterns:
      - "bomb"
    profiles:
      strict:
        secrets: block
        pii: redact
        prompt_injection: block
        blocklist: block
      standard:
        secrets: block
        pii: redact
        prompt_injection: flag
        blocklist: block

Each profile maps detector name -> action (allow|redact|block|flag), applied
to both directions. `load_profiles` returns {name: PolicyEngine}.
"""

from __future__ import annotations

import yaml

from .detectors import BlocklistDetector, PIIDetector, PromptInjectionDetector, SecretsDetector
from .policy import PolicyEngine, PolicyRule

_DETECTOR_CLASSES = {
    "pii": PIIDetector,
    "secrets": SecretsDetector,
    "prompt_injection": PromptInjectionDetector,
}

_VALID_ACTIONS = {"allow", "redact", "block", "flag"}


def load_profiles(path: str) -> tuple[dict[str, PolicyEngine], str]:
    """Load YAML policy file. Returns ({profile_name: engine}, default_name)."""
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}

    blocklist_patterns = cfg.get("blocklist_patterns", [])
    profiles_cfg = cfg.get("profiles", {"standard": {}})
    default_name = cfg.get("default_profile", "standard")
    if default_name not in profiles_cfg:
        raise ValueError(f"default_profile {default_name!r} not defined in profiles")

    engines: dict[str, PolicyEngine] = {}
    for name, rules_cfg in profiles_cfg.items():
        detectors = [cls() for cls in _DETECTOR_CLASSES.values()]
        detectors.append(BlocklistDetector(blocklist_patterns))
        rules = []
        for detector_name, action in (rules_cfg or {}).items():
            if detector_name not in _DETECTOR_CLASSES and detector_name != "blocklist":
                raise ValueError(f"unknown detector {detector_name!r} in profile {name!r}")
            if action not in _VALID_ACTIONS:
                raise ValueError(f"invalid action {action!r} in profile {name!r}")
            rules.append(PolicyRule(detector_name, None, "both", action))
        engines[name] = PolicyEngine(detectors, rules)
    return engines, default_name


def default_profiles_yaml() -> str:
    """Starter policy file content."""
    return """\
# Argus security policy: named profiles, one per key.
default_profile: standard

blocklist_patterns:
  # - "competitor-name"

profiles:
  # Maximum caution: injections blocked, everything enforced both ways.
  strict:
    secrets: block
    pii: redact
    prompt_injection: block
    blocklist: block

  # Recommended default: secrets never pass, PII redacted, injections flagged.
  standard:
    secrets: block
    pii: redact
    prompt_injection: flag
    blocklist: block

  # Visibility without enforcement: watch what fires before tightening.
  permissive:
    secrets: block
    pii: flag
    prompt_injection: flag
    blocklist: allow
"""
