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
from .profiles import DetectionProfile


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
    def __init__(self, detectors: list[Detector], rules: list[PolicyRule],
                 profile: DetectionProfile | None = None, judge=None):
        self.detectors = {d.name: d for d in detectors}
        self.rules = rules
        # Optional tunable detection profile + LLM judge second stage.
        # With profile=None the engine behaves exactly as before.
        self.profile = profile
        self.judge = judge

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
        pi_acted = False  # a prompt-injection finding was acted on
        pi_conf = 0.0     # strongest prompt-injection pattern confidence
        for detector in self.detectors.values():
            for f in detector.scan(text):
                result.findings_count += 1
                if f.detector == "prompt_injection":
                    pi_conf = max(pi_conf, f.confidence)
                action = self._rule_for(f.detector, f.category, direction)
                if self.profile is not None and \
                        f.confidence < self.profile.threshold_for(f.detector):
                    # Below the profile's confidence bar: the finding is
                    # ignored, or kept visible as a flag — never enforced.
                    if self.profile.below_threshold_action == "flag" and \
                            action != "allow":
                        result.flags.append(f"{f.detector}:{f.category}")
                    continue
                tag = f"{f.detector}:{f.category}"
                if f.detector == "prompt_injection" and action in ("flag", "block"):
                    pi_acted = True
                if action == "block":
                    result.blocked = tag
                    return result
                if action == "redact":
                    result.text = _redact(result.text, f.match, f.category)
                    result.redactions.append(tag)
                elif action == "flag":
                    result.flags.append(tag)
        self._run_judge(text, direction, result, pi_acted, pi_conf)
        return result

    def _run_judge(self, text: str, direction: str, result: PolicyResult,
                   pi_acted: bool, pi_conf: float = 0.0) -> None:
        """Second stage: the LLM judge, when the profile enables it.

        Input direction only. "gated" runs it only when the pattern
        stage acted on no prompt-injection finding — the judge exists
        for the attacks patterns miss. "auto" runs it whenever the
        pattern stage did not block, and decides on the *combined*
        confidence (noisy-or of the strongest pattern confidence and
        the judge's): clear pattern cases never reach it, borderline
        pattern evidence corroborates the judge, and a judge positive
        on its own must clear the high block bar alone. A blocked
        result never reaches here (evaluate returns first).
        """
        if self.judge is None or self.profile is None or direction != "in":
            return
        settings = self.profile.judge
        if settings.mode == "off":
            return
        if settings.mode == "gated" and pi_acted:
            return
        for f in self.judge.scan(text):
            result.findings_count += 1
            tag = f"{f.detector}:{f.category}"
            confidence = f.confidence
            if settings.mode == "auto" and pi_conf > 0.0:
                confidence = 1.0 - (1.0 - pi_conf) * (1.0 - f.confidence)
            if confidence >= settings.block_at:
                result.blocked = tag
                return
            if confidence >= settings.flag_at:
                result.flags.append(tag)


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
