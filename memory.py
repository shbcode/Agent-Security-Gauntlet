"""
Risk Ledger memory system for the Adversarial Review Board.

Tracks denials, patterns, and decision history for fallback logic.
"""

from collections import deque
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from arb_models import RiskLedgerEntry, ArbDecision
import json


class RiskLedger:
    """
    In-memory ledger for tracking ARB decisions and risk patterns.
    
    Provides functionality for:
    - Recording decisions and outcomes
    - Detecting consecutive denial patterns
    - Analyzing risk trends
    - Triggering fallback mechanisms
    """
    
    def __init__(self, max_entries: int = 1000):
        """
        Initialize the risk ledger.
        
        Args:
            max_entries: Maximum number of entries to keep in memory
        """
        self.entries: deque = deque(maxlen=max_entries)
        self.max_entries = max_entries
        self._session_start = datetime.now()
    
    def add(self, entry: Dict[str, Any]) -> None:
        """
        Add a new entry to the risk ledger.
        
        Args:
            entry: Dictionary containing decision details
        """
        # Convert dict to RiskLedgerEntry if needed
        if isinstance(entry, dict):
            # Ensure required fields are present
            entry.setdefault("timestamp", datetime.now())
            entry.setdefault("defenses_triggered", [])
            
            ledger_entry = RiskLedgerEntry(**entry)
        else:
            ledger_entry = entry
        
        self.entries.append(ledger_entry)
    
    def add_from_decision(self, decision: ArbDecision, url: str, fixture: str) -> None:
        """
        Add an entry from an ARB decision.
        
        Args:
            decision: ARB decision object
            url: URL that was analyzed
            fixture: Fixture filename
        """
        entry = RiskLedgerEntry(
            decision_id=decision.decision_id,
            url=url,
            fixture=fixture,
            approved=decision.approved,
            risk_score=decision.signals.static_score,
            defenses_triggered=decision.defenses_used
        )
        
        self.entries.append(entry)
    
    def last_n(self, n: int) -> List[RiskLedgerEntry]:
        """
        Get the last N entries from the ledger.
        
        Args:
            n: Number of recent entries to retrieve
            
        Returns:
            List of recent ledger entries
        """
        if n <= 0:
            return []
        
        return list(self.entries)[-n:]
    
    def two_denials_in_a_row(self) -> bool:
        """
        Check if there have been two consecutive denials.
        
        Returns:
            True if last two decisions were denials
        """
        if len(self.entries) < 2:
            return False
        
        last_two = self.last_n(2)
        return all(not entry.approved for entry in last_two)
    
    def consecutive_denials(self, count: int = 2) -> bool:
        """
        Check for a specific number of consecutive denials.
        
        Args:
            count: Number of consecutive denials to check for
            
        Returns:
            True if last 'count' decisions were all denials
        """
        if len(self.entries) < count:
            return False
        
        recent = self.last_n(count)
        return all(not entry.approved for entry in recent)
    
    def get_denial_streak(self) -> int:
        """
        Get the current streak of consecutive denials.
        
        Returns:
            Number of consecutive denials from the end
        """
        if not self.entries:
            return 0
        
        streak = 0
        for entry in reversed(self.entries):
            if not entry.approved:
                streak += 1
            else:
                break
        
        return streak
    
    def get_risk_trend(self, window_size: int = 10) -> Dict[str, Any]:
        """
        Analyze risk trends over recent decisions.
        
        Args:
            window_size: Number of recent entries to analyze
            
        Returns:
            Dictionary with trend analysis
        """
        recent = self.last_n(window_size)
        
        if not recent:
            return {
                "average_risk": 0.0,
                "denial_rate": 0.0,
                "trend": "stable",
                "sample_size": 0
            }
        
        # Calculate metrics
        total_risk = sum(entry.risk_score for entry in recent)
        average_risk = total_risk / len(recent)
        
        denials = sum(1 for entry in recent if not entry.approved)
        denial_rate = denials / len(recent)
        
        # Determine trend (simple heuristic)
        if len(recent) >= 5:
            first_half = recent[:len(recent)//2]
            second_half = recent[len(recent)//2:]
            
            first_avg = sum(e.risk_score for e in first_half) / len(first_half)
            second_avg = sum(e.risk_score for e in second_half) / len(second_half)
            
            if second_avg > first_avg + 0.5:
                trend = "increasing"
            elif second_avg < first_avg - 0.5:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "average_risk": round(average_risk, 2),
            "denial_rate": round(denial_rate, 2),
            "trend": trend,
            "sample_size": len(recent),
            "current_streak": self.get_denial_streak()
        }
    
    def get_fixture_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get statistics grouped by fixture.
        
        Returns:
            Dictionary mapping fixture names to their stats
        """
        fixture_stats = {}
        
        for entry in self.entries:
            fixture = entry.fixture
            if fixture not in fixture_stats:
                fixture_stats[fixture] = {
                    "total_attempts": 0,
                    "denials": 0,
                    "approvals": 0,
                    "average_risk": 0.0,
                    "common_defenses": {}
                }
            
            stats = fixture_stats[fixture]
            stats["total_attempts"] += 1
            
            if entry.approved:
                stats["approvals"] += 1
            else:
                stats["denials"] += 1
            
            # Track defenses
            for defense in entry.defenses_triggered:
                if defense not in stats["common_defenses"]:
                    stats["common_defenses"][defense] = 0
                stats["common_defenses"][defense] += 1
        
        # Calculate averages and rates
        for fixture, stats in fixture_stats.items():
            if stats["total_attempts"] > 0:
                stats["denial_rate"] = stats["denials"] / stats["total_attempts"]
                
                # Calculate average risk for this fixture
                fixture_entries = [e for e in self.entries if e.fixture == fixture]
                if fixture_entries:
                    total_risk = sum(e.risk_score for e in fixture_entries)
                    stats["average_risk"] = total_risk / len(fixture_entries)
        
        return fixture_stats
    
    def should_trigger_fallback(self, max_denials: int = 2) -> bool:
        """
        Determine if fallback should be triggered based on denial patterns.
        
        Args:
            max_denials: Maximum consecutive denials before fallback
            
        Returns:
            True if fallback should be triggered
        """
        return self.consecutive_denials(max_denials)
    
    def get_session_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current session.
        
        Returns:
            Dictionary with session statistics
        """
        if not self.entries:
            return {
                "session_duration": str(datetime.now() - self._session_start),
                "total_decisions": 0,
                "approvals": 0,
                "denials": 0,
                "unique_fixtures": 0,
                "risk_trend": self.get_risk_trend()
            }
        
        total_decisions = len(self.entries)
        approvals = sum(1 for entry in self.entries if entry.approved)
        denials = total_decisions - approvals
        unique_fixtures = len(set(entry.fixture for entry in self.entries))
        
        return {
            "session_duration": str(datetime.now() - self._session_start),
            "total_decisions": total_decisions,
            "approvals": approvals,
            "denials": denials,
            "approval_rate": round(approvals / total_decisions, 2) if total_decisions > 0 else 0,
            "unique_fixtures": unique_fixtures,
            "current_denial_streak": self.get_denial_streak(),
            "risk_trend": self.get_risk_trend()
        }
    
    def export_json(self) -> str:
        """
        Export ledger entries as JSON string.
        
        Returns:
            JSON string representation of all entries
        """
        entries_dict = []
        for entry in self.entries:
            entry_dict = entry.dict()
            # Convert datetime to string for JSON serialization
            entry_dict["timestamp"] = entry_dict["timestamp"].isoformat()
            entries_dict.append(entry_dict)
        
        return json.dumps({
            "session_start": self._session_start.isoformat(),
            "export_time": datetime.now().isoformat(),
            "total_entries": len(entries_dict),
            "entries": entries_dict
        }, indent=2)
    
    def clear(self) -> None:
        """Clear all entries from the ledger."""
        self.entries.clear()
        self._session_start = datetime.now()


# Global risk ledger instance
_global_ledger = RiskLedger()


def get_risk_ledger() -> RiskLedger:
    """Get the global risk ledger instance."""
    return _global_ledger


def reset_risk_ledger() -> None:
    """Reset the global risk ledger."""
    global _global_ledger
    _global_ledger = RiskLedger()


if __name__ == "__main__":
    # Test the risk ledger
    ledger = RiskLedger()
    
    # Add some test entries
    test_entries = [
        {
            "decision_id": "test_1",
            "url": "http://localhost/safe.html",
            "fixture": "safe_store.html",
            "approved": True,
            "risk_score": 0,
            "defenses_triggered": []
        },
        {
            "decision_id": "test_2", 
            "url": "http://localhost/trap.html",
            "fixture": "trap_hidden_text.html",
            "approved": False,
            "risk_score": 4,
            "defenses_triggered": ["Static Analysis", "Context Minimization"]
        },
        {
            "decision_id": "test_3",
            "url": "http://localhost/trap2.html", 
            "fixture": "trap_html_comment.html",
            "approved": False,
            "risk_score": 3,
            "defenses_triggered": ["Static Analysis"]
        }
    ]
    
    for entry in test_entries:
        ledger.add(entry)
    
    print("Risk Ledger Test:")
    print(f"Total entries: {len(ledger.entries)}")
    print(f"Two denials in a row: {ledger.two_denials_in_a_row()}")
    print(f"Denial streak: {ledger.get_denial_streak()}")
    print(f"Should trigger fallback: {ledger.should_trigger_fallback()}")
    
    print("\nRisk trend:")
    trend = ledger.get_risk_trend()
    for key, value in trend.items():
        print(f"  {key}: {value}")
    
    print("\nFixture stats:")
    fixture_stats = ledger.get_fixture_stats()
    for fixture, stats in fixture_stats.items():
        print(f"  {fixture}: {stats['denial_rate']:.1%} denial rate")
