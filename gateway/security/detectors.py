"""Pluggable detectors: each scans text and reports typed findings.

Detectors never decide what happens — the policy engine does. Add new ones by
subclassing Detector (an ML-based detector slots in the same way).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Finding:
    detector: str      # which detector fired
    category: str      # e.g. "EMAIL", "AWS_KEY", "PROMPT_INJECTION"
    severity: str      # "low" | "medium" | "high"
    match: str         # the matched text (redacted before audit/logging)


class Detector(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, text: str) -> list[Finding]:
        ...


class _RegexDetector(Detector):
    patterns: list[tuple[str, str, str]] = []  # (category, regex, severity)
    flags: int = 0

    def scan(self, text: str) -> list[Finding]:
        findings = []
        for category, pattern, severity in self.patterns:
            for m in re.finditer(pattern, text, self.flags):
                findings.append(Finding(
                    detector=self.name, category=category,
                    severity=severity, match=m.group(0),
                ))
        return findings


class PIIDetector(_RegexDetector):
    """Personal data that should be redacted before reaching a model."""

    name = "pii"
    patterns = [
        ("EMAIL", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "medium"),
        ("PHONE", r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", "medium"),
        ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", "high"),
        ("CREDIT_CARD", r"\b(?:\d[ -]?){13,16}\b", "high"),
        ("IP_ADDRESS", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "low"),
    ]


class SecretsDetector(_RegexDetector):
    """Credentials that must never reach a model — block, don't redact."""

    name = "secrets"
    patterns = [
        ("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b", "high"),
        ("AWS_SECRET", r"\baws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{20,}\b", "high"),
        ("PRIVATE_KEY", r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "high"),
        ("GITHUB_TOKEN", r"\bghp_[A-Za-z0-9]{20,}\b", "high"),
        ("OPENAI_KEY", r"\bsk-[a-zA-Z0-9_-]{16,}\b", "high"),
        ("GENERIC_SECRET", r"(?i)\b(api[_-]?key|secret|password)\s*[:=]\s*\S{8,}\b", "medium"),
    ]


class PromptInjectionDetector(_RegexDetector):
    """Heuristic jailbreak / instruction-override detection (input side)."""

    name = "prompt_injection"
    flags = re.IGNORECASE
    patterns = [
        ("INSTRUCTION_OVERRIDE",
         r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier)\s+(instructions|prompts|rules)\b",
         "high"),
        ("ROLE_OVERRIDE",
         r"\b(you are now|act as|pretend (to be|you are)|simulate)\b.{0,40}\b(system|admin|root|developer)\b",
         "high"),
        ("SYSTEM_PROMPT_PROBE",
         r"\b(reveal|show|print|repeat|output)\b.{0,30}\b(system prompt|initial instructions|your instructions)\b",
         "high"),
        ("ENCODERD_PAYLOAD",
         r"\b(base64|hex|rot13)[ -]?(decode|decode it|encoded)\b", "medium"),
        ("JAILBREAK_KNOWN",
         r"\b(DAN|jailbreak|do anything now|unfiltered|no restrictions)\b", "medium"),
    ]


class BlocklistDetector(Detector):
    """Deployment-specific blocked phrases/patterns."""

    name = "blocklist"

    def __init__(self, patterns: list[str] | None = None):
        self.patterns = patterns or []

    def scan(self, text: str) -> list[Finding]:
        findings = []
        for p in self.patterns:
            if re.search(p, text, re.IGNORECASE):
                findings.append(Finding(
                    detector=self.name, category="BLOCKED_TERM",
                    severity="high", match=p,
                ))
        return findings
