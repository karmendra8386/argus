"""Security layer: pluggable detectors + policy engine + audit.

Every request passes through the policy engine on the way in and on the way
out, before any model — OpenAI, Anthropic, Bedrock, self-hosted, anything —
ever sees it.
"""

from .detectors import (
    BlocklistDetector,
    Detector,
    Finding,
    PIIDetector,
    PromptInjectionDetector,
    SecretsDetector,
)
from .judge import LLMJudgeDetector
from .policy import PolicyEngine, PolicyResult, PolicyRule, default_policy
from .profiles import PRESETS, DetectionProfile, JudgeSettings

__all__ = [
    "BlocklistDetector",
    "Detector",
    "Finding",
    "PIIDetector",
    "PromptInjectionDetector",
    "SecretsDetector",
    "LLMJudgeDetector",
    "PolicyEngine",
    "PolicyResult",
    "PolicyRule",
    "default_policy",
    "DetectionProfile",
    "JudgeSettings",
    "PRESETS",
]
