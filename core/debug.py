from datetime import datetime
from core.config import DEBUG

def debug(stage: str, **data) -> None:
    if not DEBUG:
        return

    ts = datetime.now().strftime("%H:%M:%S")
    details = ", ".join(f"{k}={v!r}" for k, v in data.items())
    print(f"[{ts}] {stage}" + (f" | {details}" if details else ""))

def debug_hybrid_score(
    rule_score: int,
    ai_score: int | None,
    final_score: int,
    ai_used: bool,
    ai_capped: bool,
) -> None:
    debug(
        "HYBRID_SCORE",
        rule_score=rule_score,
        ai_score=ai_score,
        final_score=final_score,
        ai_used=ai_used,
        ai_capped=ai_capped,
    )