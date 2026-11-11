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
to both directions. A profile may also carry tuning keys — `preset`
(strict|balanced|quiet), `thresholds`, `below_threshold_action`, `judge` —
which build a DetectionProfile (see profiles.py). `load_profiles` returns
({name: PolicyEngine}, default_name).
"""

from __future__ import annotations

import copy

import yaml

from .detectors import BlocklistDetector, PIIDetector, PromptInjectionDetector, SecretsDetector
from .judge import LLMJudgeDetector
from .policy import PolicyEngine, PolicyRule
from .profiles import PRESETS, DetectionProfile

_DETECTOR_CLASSES = {
    "pii": PIIDetector,
    "secrets": SecretsDetector,
    "prompt_injection": PromptInjectionDetector,
}

_VALID_ACTIONS = {"allow", "redact", "block", "flag"}
_RESERVED_KEYS = {"preset", "judge", "thresholds", "below_threshold_action"}


def _detection_profile(name: str, rules_cfg: dict) -> DetectionProfile | None:
    """Build a DetectionProfile from a profile's tuning keys, if any.

    `preset: strict|balanced|quiet` starts from that preset; explicit
    `thresholds`, `below_threshold_action`, and `judge` keys override.
    Profiles with no tuning keys keep the engine's legacy behaviour.
    """
    if not any(k in rules_cfg for k in _RESERVED_KEYS):
        return None
    preset_name = rules_cfg.get("preset", "balanced")
    if preset_name not in PRESETS:
        raise ValueError(f"unknown preset {preset_name!r} in profile {name!r}")
    profile = copy.deepcopy(PRESETS[preset_name])
    profile.name = name
    for detector, threshold in (rules_cfg.get("thresholds") or {}).items():
        if detector not in _DETECTOR_CLASSES and detector != "blocklist":
            raise ValueError(f"unknown detector {detector!r} in profile {name!r}")
        profile.thresholds[detector] = float(threshold)
    if "below_threshold_action" in rules_cfg:
        action = rules_cfg["below_threshold_action"]
        if action not in ("allow", "flag"):
            raise ValueError(
                f"invalid below_threshold_action {action!r} in profile {name!r}")
        profile.below_threshold_action = action
    for key, value in (rules_cfg.get("judge") or {}).items():
        if not hasattr(profile.judge, key):
            raise ValueError(f"unknown judge setting {key!r} in profile {name!r}")
        setattr(profile.judge, key, value)
    if profile.judge.mode not in ("off", "gated", "always"):
        raise ValueError(
            f"invalid judge mode {profile.judge.mode!r} in profile {name!r}")
    return profile


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
        rules_cfg = rules_cfg or {}
        detectors = [cls() for cls in _DETECTOR_CLASSES.values()]
        detectors.append(BlocklistDetector(blocklist_patterns))
        rules = []
        for detector_name, action in rules_cfg.items():
            if detector_name in _RESERVED_KEYS:
                continue
            if detector_name not in _DETECTOR_CLASSES and detector_name != "blocklist":
                raise ValueError(f"unknown detector {detector_name!r} in profile {name!r}")
            if action not in _VALID_ACTIONS:
                raise ValueError(f"invalid action {action!r} in profile {name!r}")
            rules.append(PolicyRule(detector_name, None, "both", action))
        profile = _detection_profile(name, rules_cfg)
        judge = None
        if profile is not None and profile.judge.mode != "off":
            j = profile.judge
            judge = LLMJudgeDetector(base_url=j.base_url, model=j.model,
                                     api_key=j.api_key, timeout=j.timeout)
        engines[name] = PolicyEngine(detectors, rules, profile=profile, judge=judge)
    return engines, default_name


def default_profiles_yaml() -> str:
    """Starter policy file content."""
    return """\
# Argus security policy: named profiles, one per key.
# strict / balanced / quiet are TUNABLE detection profiles (see
# gateway/security/profiles.py): they set per-detector confidence
# thresholds and whether the local LLM judge second stage runs.
# `standard` is the legacy action-only profile, kept unchanged for
# keys that already reference it. The judge endpoint defaults to a
# local Ollama server; override per profile under `judge:`.
default_profile: balanced

blocklist_patterns:
  # - "competitor-name"

profiles:
  # Catch everything, accept false alarms: low thresholds, injections
  # blocked, judge always on with a low block bar.
  strict:
    preset: strict
    secrets: block
    pii: redact
    prompt_injection: block
    blocklist: block

  # Recommended default: patterns flag at medium confidence and up;
  # the judge runs only on pattern misses and blocks when confident.
  balanced:
    preset: balanced
    secrets: block
    pii: redact
    prompt_injection: flag
    blocklist: block

  # Minimise false alarms: only high-confidence pattern findings act,
  # injections flagged never blocked, judge off.
  quiet:
    preset: quiet
    secrets: block
    pii: redact
    prompt_injection: flag
    blocklist: block

  # Legacy profile (no tuning): the pre-tuning behaviour.
  standard:
    secrets: block
    pii: redact
    prompt_injection: flag
    blocklist: block
"""
