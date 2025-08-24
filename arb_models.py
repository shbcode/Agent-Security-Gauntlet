"""
Pydantic models for the Adversarial Review Board (ARB).

Defines data structures for plan contracts, signals, decisions, and juror votes.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class PlanContract(BaseModel):
    """Contract defining the allowed scope and objectives for a plan step."""
    
    domain: str = Field(..., description="Allowed domain (e.g., 'localhost')")
    tool: str = Field(..., description="Allowed tool (e.g., 'read_page')")
    objective_tags: List[str] = Field(..., description="Allowed objective keywords")
    
    class Config:
        schema_extra = {
            "example": {
                "domain": "localhost",
                "tool": "read_page", 
                "objective_tags": ["refund", "policy", "warranty"]
            }
        }


class JurorVote(BaseModel):
    """Individual juror's risk assessment vote."""
    
    juror_id: str = Field(..., description="Unique juror identifier")
    risk_score: int = Field(..., ge=0, le=5, description="Risk level 0-5")
    rationale: str = Field(..., description="Explanation for the risk assessment")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in assessment")
    response_time_ms: Optional[int] = Field(None, description="Time taken to respond")
    
    class Config:
        schema_extra = {
            "example": {
                "juror_id": "strict_security",
                "risk_score": 4,
                "rationale": "Content contains hidden instructions to ignore safety protocols",
                "confidence": 0.9,
                "response_time_ms": 1250
            }
        }


class ArbSignals(BaseModel):
    """All signals collected by the ARB for decision making."""
    
    # Static Analysis Signals
    allowlist_ok: bool = Field(..., description="Domain allowlist check passed")
    static_score: int = Field(..., ge=0, le=5, description="Static analysis risk score")
    static_patterns: List[str] = Field(default_factory=list, description="Matched suspicious patterns")
    
    # LLM Juror Signals (optional)
    llm_votes: Optional[List[JurorVote]] = Field(None, description="LLM juror risk assessments")
    llm_median_risk: Optional[float] = Field(None, description="Median risk from LLM jurors")
    llm_consensus: Optional[bool] = Field(None, description="Whether jurors reached consensus")
    
    # Plan Conformance Signals
    conformance_ok: bool = Field(..., description="Plan conformance check passed")
    conformance_reasons: List[str] = Field(default_factory=list, description="Conformance check details")
    
    # Metadata
    analysis_time_ms: int = Field(default=0, description="Total analysis time")
    timestamp: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "allowlist_ok": True,
                "static_score": 4,
                "static_patterns": ["ignore.*instructions", "reveal.*system"],
                "llm_votes": [
                    {
                        "juror_id": "strict_security",
                        "risk_score": 4,
                        "rationale": "Hidden instructions detected",
                        "confidence": 0.9
                    }
                ],
                "llm_median_risk": 4.0,
                "llm_consensus": True,
                "conformance_ok": True,
                "conformance_reasons": ["Domain allowed", "Tool permitted"],
                "analysis_time_ms": 1500
            }
        }


class ArbDecision(BaseModel):
    """Final decision from the Adversarial Review Board."""
    
    # Core Decision
    approved: bool = Field(..., description="Whether the action is approved")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in decision")
    
    # Defense Information
    defenses_used: List[str] = Field(default_factory=list, description="Security defenses that were triggered")
    reasons: List[str] = Field(default_factory=list, description="Human-readable decision reasons")
    
    # Content Processing
    sanitized_text: str = Field(default="", description="Safe, visible text for execution")
    content_modified: bool = Field(default=False, description="Whether content was sanitized")
    
    # Plan Revision (when denied)
    revised_step: Optional[Dict[str, Any]] = Field(None, description="Suggested safe plan revision")
    fallback_recommended: bool = Field(default=False, description="Whether fallback is recommended")
    
    # Analysis Details
    signals: ArbSignals = Field(..., description="All collected analysis signals")
    
    # Metadata
    decision_id: str = Field(default_factory=lambda: f"arb_{datetime.now().strftime('%Y%m%d_%H%M%S')}", 
                           description="Unique decision identifier")
    
    class Config:
        schema_extra = {
            "example": {
                "approved": False,
                "confidence": 0.95,
                "defenses_used": ["Static Analysis", "LLM Panel", "Context Minimization"],
                "reasons": ["Hidden malicious instructions detected", "High risk consensus from jurors"],
                "sanitized_text": "Store policy: Refunds within 30 days with receipt.",
                "content_modified": True,
                "revised_step": {
                    "action": "extract_facts",
                    "context": "visible_text_only",
                    "restrictions": ["no_hidden_content", "facts_only"]
                },
                "fallback_recommended": False,
                "signals": {
                    "allowlist_ok": True,
                    "static_score": 4,
                    "static_patterns": ["ignore.*instructions"],
                    "conformance_ok": True
                }
            }
        }


class RiskLedgerEntry(BaseModel):
    """Entry in the risk ledger for tracking denials and patterns."""
    
    timestamp: datetime = Field(default_factory=datetime.now)
    decision_id: str = Field(..., description="Reference to ARB decision")
    url: str = Field(..., description="URL that was analyzed")
    fixture: str = Field(..., description="Fixture filename")
    approved: bool = Field(..., description="Whether action was approved")
    risk_score: int = Field(..., ge=0, le=5, description="Overall risk score")
    defenses_triggered: List[str] = Field(default_factory=list)
    
    class Config:
        schema_extra = {
            "example": {
                "decision_id": "arb_20241201_143022",
                "url": "http://localhost/trap_hidden_text.html",
                "fixture": "trap_hidden_text.html",
                "approved": False,
                "risk_score": 4,
                "defenses_triggered": ["Static Analysis", "Context Minimization"]
            }
        }


class ARBSettings(BaseModel):
    """Runtime settings for ARB operation."""
    
    llm_enabled: bool = Field(default=False)
    juror_count: int = Field(default=0, ge=0, le=3)
    vote_timeout: float = Field(default=2.0, gt=0)
    static_threshold: int = Field(default=2, ge=0, le=5)
    llm_threshold: int = Field(default=2, ge=0, le=5)
    max_denials: int = Field(default=2, ge=1)
    
    class Config:
        schema_extra = {
            "example": {
                "llm_enabled": True,
                "juror_count": 3,
                "vote_timeout": 2.0,
                "static_threshold": 2,
                "llm_threshold": 2,
                "max_denials": 2
            }
        }


if __name__ == "__main__":
    # Test model creation
    contract = PlanContract(
        domain="localhost",
        tool="read_page",
        objective_tags=["refund", "policy"]
    )
    
    signals = ArbSignals(
        allowlist_ok=True,
        static_score=3,
        static_patterns=["ignore.*instructions"],
        conformance_ok=True
    )
    
    decision = ArbDecision(
        approved=False,
        defenses_used=["Static Analysis"],
        reasons=["Suspicious patterns detected"],
        sanitized_text="Safe content only",
        signals=signals
    )
    
    print("Models created successfully:")
    print(f"Contract: {contract}")
    print(f"Decision: {decision.approved}")
    print(f"Signals: {len(signals.static_patterns)} patterns")
