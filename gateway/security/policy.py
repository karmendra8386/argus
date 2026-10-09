"""Policy engine: detectors find, policies decide.

Actions: allow | redact | block | flag
  - redact: replace matches with [REDACTED:CATEGORY], request continues
  - block:  reject the request/response outright
  - flag:   allow through but mark in audit + response metadata
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import (
    BlocklistDetector,
    Detector,
    PIIDetector,
    PromptInjectionDetector,
    SecretsDetector,
)


@dataclass
class PolicyRule:
    detector: str            # detector name, or "*" for any
    category: str | None     # None = all categories from that detector
    direction: str           # "in" | "out" | "both"
    action: str              # "allow" | "redact" | "block" | "flag"


@dataclass
class PolicyResult:
    text: str                                # possibly redacted
    blocked: str | None = None               # "detector:category" if blocked
    flags: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    findings_count: int = 0


def _redact(text: str, match: str, category: str) -> str:
    return text.replace(match, f"[REDACTED:{category}]", 1)


class PolicyEngine:
    def __init__(self, detectors: list[Detector], rules: list[PolicyRule]):
        self.detectors = {d.name: d for d in detectors}
        self.rules = rules

    def _rule_for(self, detector: str, category: str, direction: str) -> str:
        for r in self.rules:
            if r.direction not in (direction, "both"):
                continue
            if r.detector not in (detector, "*"):
                continue
            if r.category is not None and r.category != category:
                continue
            return r.action
        return "allow"

    def evaluate(self, text: str, direction: str) -> PolicyResult:
        result = PolicyResult(text=text)
        for detector in self.detectors.values():
            for f in detector.scan(text):
                result.findings_count += 1
                action = self._rule_for(f.detector, f.category, direction)
                tag = f"{f.detector}:{f.category}"
                if action == "block":
                    result.blocked = tag
                    return result
                if action == "redact":
                    result.text = _redact(result.text, f.match, f.category)
                    result.redactions.append(tag)
                elif action == "flag":
                    result.flags.append(tag)
        return result


def default_policy(blocklist: list[str] | None = None) -> PolicyEngine:
    """Sensible defaults: secrets never pass, PII is redacted, injections flagged."""
    detectors: list[Detector] = [
        PIIDetector(),
        SecretsDetector(),
        PromptInjectionDetector(),
        BlocklistDetector(blocklist),
    ]
    rules = [
        PolicyRule("secrets", None, "both", "block"),
        PolicyRule("pii", None, "both", "redact"),
        PolicyRule("prompt_injection", None, "in", "flag"),
        PolicyRule("blocklist", None, "both", "block"),
    ]
    return PolicyEngine(detectors, rules)
