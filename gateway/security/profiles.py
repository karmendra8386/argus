"""Tunable detection profiles: where in the catch/false-alarm range to sit.

A profile tunes *detection*, not just the action taken after a finding:

  - `thresholds`: per-detector minimum confidence for a finding to be
    acted on. Findings below it fall to `below_threshold_action`
    ("allow" = ignored, "flag" = still logged and marked).
  - `judge`: whether the LLM judge second stage runs — "off", "gated"
    (only when the pattern stage produced no acted-on prompt-injection
    finding — the judge exists for what patterns miss), or "always"
    (every non-blocked input) — and the confidences at which a judge
    positive flags or blocks.

Presets span the range measured on Argus-Bench (264 frozen cases):

  - strict:   catch everything, accept false alarms. Low thresholds,
              injections blocked, judge always on with a low block bar.
  - balanced: the default. Patterns flag at medium confidence and up;
              the judge, gated to pattern misses, blocks only when it
              is confident and flags below that.
  - quiet:    minimise false alarms. Only high-confidence pattern
              findings act, injections are never blocked on pattern
              evidence alone, and the judge stays off.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class JudgeSettings:
    mode: str = "off"                 # "off" | "gated" | "always"
    block_at: float = 0.75            # judge confidence >= this -> block
    flag_at: float = 0.45             # judge confidence >= this -> flag
    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "qwen25-local"
    api_key: str = "ollama"
    timeout: float = 120.0


@dataclass
class DetectionProfile:
    name: str
    thresholds: dict[str, float] = field(default_factory=dict)
    below_threshold_action: str = "allow"   # "allow" | "flag"
    judge: JudgeSettings = field(default_factory=JudgeSettings)

    def threshold_for(self, detector: str) -> float:
        return self.thresholds.get(detector, 0.0)


#: Preset name -> (thresholds, below_threshold_action, judge)
PRESETS: dict[str, DetectionProfile] = {
    "strict": DetectionProfile(
        name="strict",
        thresholds={"prompt_injection": 0.30, "pii": 0.30,
                    "secrets": 0.30, "blocklist": 0.0},
        below_threshold_action="flag",
        judge=JudgeSettings(mode="always", block_at=0.50, flag_at=0.35),
    ),
    "balanced": DetectionProfile(
        name="balanced",
        thresholds={"prompt_injection": 0.55, "pii": 0.35,
                    "secrets": 0.30, "blocklist": 0.0},
        below_threshold_action="allow",
        judge=JudgeSettings(mode="gated", block_at=0.75, flag_at=0.45),
    ),
    "quiet": DetectionProfile(
        name="quiet",
        thresholds={"prompt_injection": 0.85, "pii": 0.35,
                    "secrets": 0.30, "blocklist": 0.0},
        below_threshold_action="allow",
        judge=JudgeSettings(mode="off"),
    ),
}
