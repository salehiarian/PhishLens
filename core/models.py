from dataclasses import dataclass, field

@dataclass
class ParsedEmail:
    subject: str | None = None
    body_text: str | None = None
    from_raw: str | None = None
    from_email: str | None = None
    from_domain: str | None = None

    reply_to_raw: str | None = None
    reply_to_email: str | None = None
    reply_to_domain: str | None = None

    urls: list[str] = field(default_factory=list)
    url_domains: list[str] = field(default_factory=list)
    suspicious_phrases: list[str] = field(default_factory=list)



@dataclass
class RuleResult:
    rule_id: str
    name: str
    triggered: bool
    weight: int
    reason: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    score: int
    risk_level: str
    confidence: int
    triggered_rules: list[RuleResult] = field(default_factory=list)
    top_reasons: list[str] = field(default_factory=list)

@dataclass
class AIResult:
    explanation: str
    suspicion_score: int | None = None
    category: str | None = None
    confidence_label: str | None = None
    reasons: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    ticket_summary: str = ""
    model_used: str | None = None
    used_ai: bool = False
    error: str | None = None

@dataclass
class AnalysisPayload:
    parsed: ParsedEmail
    analysis: AnalysisResult
    ai_result: AIResult
    next_steps: list[str]
    ticket_summary: str